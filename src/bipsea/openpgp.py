"""
Pure-Python OpenPGP packet construction for BIP85 GPG key export.

Produces ASCII-armored transferable secret keys importable by GnuPG 2.
Implements just enough of RFC 4880 / RFC 6637 / draft-koch-eddsa-for-openpgp
to build unprotected secret-key packets with self-signatures.
"""

import base64
import hashlib
import struct
from typing import Callable, Dict, List, Optional, Tuple

from ecdsa import (
    BRAINPOOLP256r1,
    BRAINPOOLP384r1,
    BRAINPOOLP512r1,
    NIST256p,
    NIST384p,
    NIST521p,
    SECP256k1,
    Ed25519,
    SigningKey,
)

# ── timestamps ───────────────────────────────────────────────────────────────
GENESIS_TIMESTAMP = 1231006505  # Bitcoin genesis block, '2009-01-03 18:15:05' UTC

# ── algorithm identifiers ───────────────────────────────────────────────────
ALGO_RSA = 1
ALGO_ECDH = 18
ALGO_ECDSA = 19
ALGO_EDDSA = 22

# hash
HASH_SHA256 = 8
HASH_SHA384 = 9
HASH_SHA512 = 10

# symmetric cipher
SYM_AES128 = 7
SYM_AES256 = 9

# compression
COMP_NONE = 0
COMP_ZIP = 1
COMP_ZLIB = 2

# ── signature types ─────────────────────────────────────────────────────────
SIG_POSITIVE_CERT = 0x13
SIG_SUBKEY_BINDING = 0x18
SIG_PRIMARY_KEY_BINDING = 0x19

# ── key capability flags ────────────────────────────────────────────────────
FLAG_CERTIFY = 0x01
FLAG_SIGN = 0x02
FLAG_ENCRYPT_COMM = 0x04
FLAG_ENCRYPT_STOR = 0x08
FLAG_AUTHENTICATE = 0x20

# ── subpacket types ─────────────────────────────────────────────────────────
SUBPKT_CREATION_TIME = 2
SUBPKT_KEY_EXPIRY = 9
SUBPKT_PREFERRED_SYMMETRIC = 11
SUBPKT_ISSUER_KEY_ID = 16
SUBPKT_PREFERRED_HASH = 21
SUBPKT_PREFERRED_COMPRESSION = 22
SUBPKT_KEY_FLAGS = 27
SUBPKT_FEATURES = 30
SUBPKT_EMBEDDED_SIGNATURE = 32
SUBPKT_ISSUER_FINGERPRINT = 33

# ── curve OIDs (DER encoded, without length prefix) ─────────────────────────
OID_ED25519 = bytes.fromhex("2b06010401da470f01")
OID_CURVE25519 = bytes.fromhex("2b060104019755010501")
OID_SECP256K1 = bytes.fromhex("2b8104000a")
OID_NIST_P256 = bytes.fromhex("2a8648ce3d030107")
OID_NIST_P384 = bytes.fromhex("2b81040022")
OID_NIST_P521 = bytes.fromhex("2b81040023")
OID_BRAINPOOL_P256R1 = bytes.fromhex("2b2403030208010107")
OID_BRAINPOOL_P384R1 = bytes.fromhex("2b240303020801010b")
OID_BRAINPOOL_P512R1 = bytes.fromhex("2b240303020801010d")

# ── X25519 helpers (RFC 7748) ───────────────────────────────────────────────
_X25519_P = (1 << 255) - 19
_X25519_A24 = 121665


def _x25519_clamp_int(k_bytes: bytes) -> int:
    k = bytearray(k_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _x25519_ladder(k_int: int, u_int: int) -> int:
    p = _X25519_P
    x_2, z_2 = 1, 0
    x_3, z_3 = u_int, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        A = (x_2 + z_2) % p
        AA = A * A % p
        B = (x_2 - z_2) % p
        BB = B * B % p
        E = (AA - BB) % p
        C = (x_3 + z_3) % p
        D = (x_3 - z_3) % p
        DA = D * A % p
        CB = C * B % p
        x_3 = pow(DA + CB, 2, p)
        z_3 = u_int * pow(DA - CB, 2, p) % p
        x_2 = AA * BB % p
        z_2 = E * (AA + _X25519_A24 * E) % p
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    return x_2 * pow(z_2, p - 2, p) % p


def x25519_public_key(secret_bytes: bytes) -> bytes:
    """Compute the 32-byte X25519 public key from a 32-byte secret."""
    k = _x25519_clamp_int(secret_bytes)
    u = _x25519_ladder(k, 9)
    return u.to_bytes(32, "little")


# ── low-level OpenPGP encoding ──────────────────────────────────────────────


def encode_mpi(n: int) -> bytes:
    """Encode *n* as an OpenPGP Multi-Precision Integer."""
    if n == 0:
        return b"\x00\x00"
    bit_len = n.bit_length()
    byte_len = (bit_len + 7) // 8
    return struct.pack(">H", bit_len) + n.to_bytes(byte_len, "big")


def _packet_header(tag: int, body_len: int) -> bytes:
    """New-format OpenPGP packet header."""
    hdr = bytes([0xC0 | tag])
    if body_len < 192:
        hdr += bytes([body_len])
    elif body_len < 8384:
        body_len -= 192
        hdr += bytes([((body_len >> 8) + 192) & 0xFF, body_len & 0xFF])
    else:
        hdr += b"\xff" + struct.pack(">I", body_len)
    return hdr


def encode_packet(tag: int, body: bytes) -> bytes:
    return _packet_header(tag, len(body)) + body


def _encode_subpacket(sptype: int, body: bytes) -> bytes:
    total = 1 + len(body)  # type byte + body
    if total < 192:
        return bytes([total, sptype]) + body
    elif total < 16320:
        total -= 192
        return bytes([((total >> 8) + 192) & 0xFF, total & 0xFF, sptype]) + body
    else:
        return b"\xff" + struct.pack(">I", total) + bytes([sptype]) + body


def _encode_subpackets(subpkts: List[bytes]) -> bytes:
    data = b"".join(subpkts)
    return struct.pack(">H", len(data)) + data


# ── key fingerprint / ID ────────────────────────────────────────────────────


def key_fingerprint_v4(key_body: bytes) -> bytes:
    """SHA-1 fingerprint for a v4 key (20 bytes)."""
    prefix = b"\x99" + struct.pack(">H", len(key_body))
    return hashlib.sha1(prefix + key_body).digest()


def key_id_from_fingerprint(fp: bytes) -> bytes:
    return fp[-8:]


# ── key-material helpers ────────────────────────────────────────────────────

# Map (key_type, key_bits) → OID for signing/certify/auth algorithms
_SIGN_OID = {
    (1, 256): OID_ED25519,
    (2, 256): OID_SECP256K1,
    (3, 256): OID_NIST_P256,
    (3, 384): OID_NIST_P384,
    (3, 521): OID_NIST_P521,
    (4, 256): OID_BRAINPOOL_P256R1,
    (4, 384): OID_BRAINPOOL_P384R1,
    (4, 512): OID_BRAINPOOL_P512R1,
}

# Map (key_type, key_bits) → OID for encryption subkey
_ENC_OID = {
    (1, 256): OID_CURVE25519,
    (2, 256): OID_SECP256K1,
    (3, 256): OID_NIST_P256,
    (3, 384): OID_NIST_P384,
    (3, 521): OID_NIST_P521,
    (4, 256): OID_BRAINPOOL_P256R1,
    (4, 384): OID_BRAINPOOL_P384R1,
    (4, 512): OID_BRAINPOOL_P512R1,
}

# Map (key_type, key_bits) → ecdsa curve object (for signing/ECDSA)
_ECDSA_CURVE = {
    (2, 256): SECP256k1,
    (3, 256): NIST256p,
    (3, 384): NIST384p,
    (3, 521): NIST521p,
    (4, 256): BRAINPOOLP256r1,
    (4, 384): BRAINPOOLP384r1,
    (4, 512): BRAINPOOLP512r1,
}

# Map (key_type, key_bits) → (hash_algo_id, sym_algo_id) for ECDH KDF
_ECDH_KDF = {
    (1, 256): (HASH_SHA256, SYM_AES128),
    (2, 256): (HASH_SHA256, SYM_AES128),
    (3, 256): (HASH_SHA256, SYM_AES128),
    (3, 384): (HASH_SHA384, SYM_AES256),
    (3, 521): (HASH_SHA512, SYM_AES256),
    (4, 256): (HASH_SHA256, SYM_AES128),
    (4, 384): (HASH_SHA384, SYM_AES256),
    (4, 512): (HASH_SHA512, SYM_AES256),
}

# Map (key_type, key_bits) → hash algo for signatures
_SIG_HASH = {
    (0, 1024): HASH_SHA256,
    (0, 2048): HASH_SHA256,
    (0, 3072): HASH_SHA256,
    (0, 4096): HASH_SHA256,
    (1, 256): HASH_SHA256,
    (2, 256): HASH_SHA256,
    (3, 256): HASH_SHA256,
    (3, 384): HASH_SHA384,
    (3, 521): HASH_SHA512,
    (4, 256): HASH_SHA256,
    (4, 384): HASH_SHA384,
    (4, 512): HASH_SHA512,
}


def _hashfunc_for(hash_algo: int):
    return {HASH_SHA256: hashlib.sha256, HASH_SHA384: hashlib.sha384, HASH_SHA512: hashlib.sha512}[hash_algo]


def _make_ecdh_kdf_params(hash_id: int, sym_id: int) -> bytes:
    """3-byte KDF parameter block for ECDH."""
    return bytes([3, 1, hash_id, sym_id])


def _ecc_signing_algo(key_type: int) -> int:
    return ALGO_EDDSA if key_type == 1 else ALGO_ECDSA


# ── public-key material builders ────────────────────────────────────────────


def _build_rsa_pub_material(rsa: Dict[str, int]) -> bytes:
    return encode_mpi(rsa["n"]) + encode_mpi(rsa["e"])


def _build_rsa_sec_material(rsa: Dict[str, int]) -> bytes:
    u = pow(rsa["p"], -1, rsa["q"])
    return (
        encode_mpi(rsa["d"])
        + encode_mpi(rsa["p"])
        + encode_mpi(rsa["q"])
        + encode_mpi(u)
    )


def _build_eddsa_pub_material(
    oid: bytes, public_point: bytes
) -> bytes:
    """EdDSA public key: OID-len + OID + MPI(0x40 || point)."""
    q_with_prefix = b"\x40" + public_point
    return bytes([len(oid)]) + oid + encode_mpi(int.from_bytes(q_with_prefix, "big"))


def _build_ecdsa_pub_material(oid: bytes, public_uncompressed: bytes) -> bytes:
    """ECDSA/ECDH public key: OID-len + OID + MPI(point)."""
    return bytes([len(oid)]) + oid + encode_mpi(
        int.from_bytes(public_uncompressed, "big")
    )


def _build_ecdh_pub_material(
    oid: bytes, public_point_raw: bytes, kdf_params: bytes
) -> bytes:
    """ECDH public key: OID-len + OID + MPI(point) + KDF-len + KDF."""
    if oid in (OID_ED25519, OID_CURVE25519):
        q = b"\x40" + public_point_raw
    else:
        q = public_point_raw  # already 0x04+x+y
    return (
        bytes([len(oid)])
        + oid
        + encode_mpi(int.from_bytes(q, "big"))
        + bytes([len(kdf_params)])
        + kdf_params
    )


def _build_ecc_sec_material_mpi(
    secret_bytes: bytes, is_curve25519: bool
) -> bytes:
    """Encode ECC secret key as MPI.

    For Ed25519 / X25519 the secret bytes are reversed before MPI
    encoding (GnuPG stores these keys in native little-endian form
    and reverses when writing the big-endian MPI).
    """
    if is_curve25519:
        val = int.from_bytes(reversed(secret_bytes), "big")
    else:
        val = int.from_bytes(secret_bytes, "big")
    return encode_mpi(val)


def _clamp_x25519_secret(secret: bytes) -> bytes:
    """Apply X25519 clamping to raw secret key bytes.

    GnuPG expects the stored X25519 secret to be pre-clamped.
    """
    b = bytearray(secret)
    b[0] &= 248      # clear bits 0, 1, 2
    b[31] &= 127     # clear bit 255
    b[31] |= 64      # set bit 254
    return bytes(b)


# ── secret-key packet body ──────────────────────────────────────────────────


def build_pub_key_body(
    algo: int,
    pub_material: bytes,
    creation_time: int = GENESIS_TIMESTAMP,
) -> bytes:
    """V4 public-key body (used for fingerprint computation)."""
    body = bytes([4])  # version
    body += struct.pack(">I", creation_time)
    body += bytes([algo])
    body += pub_material
    return body


def build_key_body(
    algo: int,
    pub_material: bytes,
    sec_material: bytes,
    creation_time: int = GENESIS_TIMESTAMP,
) -> Tuple[bytes, bytes]:
    """V4 secret-key packet body (unprotected, s2k usage 0).

    Returns (full_body, pub_body) where pub_body is the public portion
    used for fingerprint computation.
    """
    pub_body = build_pub_key_body(algo, pub_material, creation_time)
    body = pub_body
    body += bytes([0])  # s2k usage: unprotected
    body += sec_material
    checksum = sum(sec_material) & 0xFFFF
    body += struct.pack(">H", checksum)
    return body, pub_body


# ── signature construction ──────────────────────────────────────────────────


def _hashed_subpackets_self_sig(
    creation_time: int, flags: int, fp: bytes
) -> bytes:
    spkts = [
        _encode_subpacket(SUBPKT_CREATION_TIME, struct.pack(">I", creation_time)),
        _encode_subpacket(SUBPKT_KEY_FLAGS, bytes([flags])),
        _encode_subpacket(
            SUBPKT_PREFERRED_SYMMETRIC,
            bytes([SYM_AES256, SYM_AES128]),
        ),
        _encode_subpacket(
            SUBPKT_PREFERRED_HASH,
            bytes([HASH_SHA512, HASH_SHA384, HASH_SHA256]),
        ),
        _encode_subpacket(
            SUBPKT_PREFERRED_COMPRESSION,
            bytes([COMP_ZLIB, COMP_ZIP, COMP_NONE]),
        ),
        _encode_subpacket(SUBPKT_FEATURES, bytes([0x01])),  # MDC
        _encode_subpacket(SUBPKT_ISSUER_FINGERPRINT, bytes([4]) + fp),
    ]
    return b"".join(spkts)


def _hashed_subpackets_subkey_binding(
    creation_time: int, flags: int, fp: bytes
) -> bytes:
    spkts = [
        _encode_subpacket(SUBPKT_CREATION_TIME, struct.pack(">I", creation_time)),
        _encode_subpacket(SUBPKT_KEY_FLAGS, bytes([flags])),
        _encode_subpacket(SUBPKT_ISSUER_FINGERPRINT, bytes([4]) + fp),
    ]
    return b"".join(spkts)


def _unhashed_subpackets(key_id: bytes) -> bytes:
    return _encode_subpacket(SUBPKT_ISSUER_KEY_ID, key_id)


def _sig_hash_input(
    message_data: bytes,
    sig_type: int,
    pub_algo: int,
    hash_algo: int,
    hashed_sub: bytes,
) -> Tuple[bytes, bytes]:
    """Build the hash input and compute the digest.

    Returns (full_hash_input, digest).
    """
    hdr = bytes([4, sig_type, pub_algo, hash_algo])
    hashed_sub_enc = _encode_subpackets([hashed_sub])
    sig_data = hdr + hashed_sub_enc
    total_len = len(sig_data)
    trailer = bytes([4, 0xFF]) + struct.pack(">I", total_len)
    full = message_data + sig_data + trailer
    h = _hashfunc_for(hash_algo)
    digest = h(full).digest()
    return full, digest


def _do_sign(
    full_hash_input: bytes,
    digest: bytes,
    signing_key,
    algo: int,
    key_type: int,
    key_bits: int,
    rsa_key: Optional[Dict] = None,
) -> bytes:
    """Produce the MPI-encoded signature value."""
    if algo == ALGO_EDDSA:
        # EdDSA in OpenPGP signs the hash digest (not the raw message)
        sig = signing_key.sign_deterministic(digest)
        # Store R and S as big-endian MPIs (matching GnuPG convention)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        return encode_mpi(r) + encode_mpi(s)
    elif algo == ALGO_ECDSA:
        sig = signing_key.sign_digest(digest)
        half = len(sig) // 2
        r = int.from_bytes(sig[:half], "big")
        s = int.from_bytes(sig[half:], "big")
        return encode_mpi(r) + encode_mpi(s)
    elif algo == ALGO_RSA:
        return encode_mpi(_rsa_sign_pkcs1v15(digest, rsa_key, _SIG_HASH[(key_type, key_bits)]))
    else:
        raise ValueError(f"Unsupported signing algorithm {algo}")


def _rsa_sign_pkcs1v15(digest: bytes, rsa: Dict[str, int], hash_algo: int) -> int:
    """PKCS#1 v1.5 signature (returns the signature integer)."""
    # DigestInfo DER prefixes for SHA-2 family
    _DI_PREFIX = {
        HASH_SHA256: bytes.fromhex("3031300d060960864801650304020105000420"),
        HASH_SHA384: bytes.fromhex("3041300d060960864801650304020205000430"),
        HASH_SHA512: bytes.fromhex("3051300d060960864801650304020305000440"),
    }
    di = _DI_PREFIX[hash_algo] + digest
    n, d = rsa["n"], rsa["d"]
    k = (n.bit_length() + 7) // 8
    pad_len = k - 3 - len(di)
    if pad_len < 8:
        raise ValueError("RSA key too short for this digest")
    em = b"\x00\x01" + (b"\xff" * pad_len) + b"\x00" + di
    m = int.from_bytes(em, "big")
    return pow(m, d, n)


def build_signature_packet(
    message_data: bytes,
    sig_type: int,
    pub_algo: int,
    hash_algo: int,
    hashed_sub: bytes,
    key_id: bytes,
    signing_key,
    key_type: int,
    key_bits: int,
    rsa_key: Optional[Dict] = None,
    embedded_sig: Optional[bytes] = None,
) -> bytes:
    """Build a complete OpenPGP v4 signature packet (tag 2)."""
    full_input, digest = _sig_hash_input(
        message_data, sig_type, pub_algo, hash_algo, hashed_sub
    )
    hash_prefix = digest[:2]

    sig_mpis = _do_sign(
        full_input, digest, signing_key, pub_algo, key_type, key_bits, rsa_key
    )

    # Build unhashed subpackets
    unhashed_parts = _unhashed_subpackets(key_id)
    if embedded_sig is not None:
        unhashed_parts += _encode_subpacket(SUBPKT_EMBEDDED_SIGNATURE, embedded_sig)
    unhashed_enc = _encode_subpackets([unhashed_parts])

    # Assemble signature body
    hdr = bytes([4, sig_type, pub_algo, hash_algo])
    hashed_enc = _encode_subpackets([hashed_sub])
    body = hdr + hashed_enc + unhashed_enc + hash_prefix + sig_mpis
    return encode_packet(2, body)


def _certification_hash_data(key_body: bytes, uid: str) -> bytes:
    """Hash prefix for a self-certification: key + UID."""
    uid_bytes = uid.encode("utf-8")
    return (
        b"\x99"
        + struct.pack(">H", len(key_body))
        + key_body
        + b"\xb4"
        + struct.pack(">I", len(uid_bytes))
        + uid_bytes
    )


def _binding_hash_data(primary_body: bytes, subkey_body: bytes) -> bytes:
    return (
        b"\x99"
        + struct.pack(">H", len(primary_body))
        + primary_body
        + b"\x99"
        + struct.pack(">H", len(subkey_body))
        + subkey_body
    )


# ── ASCII armor ─────────────────────────────────────────────────────────────

_CRC24_INIT = 0xB704CE
_CRC24_POLY = 0x1864CFB


def _crc24(data: bytes) -> int:
    crc = _CRC24_INIT
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= _CRC24_POLY
    return crc & 0xFFFFFF


def ascii_armor(data: bytes, block_type: str = "PGP PRIVATE KEY BLOCK") -> str:
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i : i + 76] for i in range(0, len(b64), 76)]
    crc = _crc24(data)
    crc_b64 = base64.b64encode(crc.to_bytes(3, "big")).decode("ascii")
    return (
        f"-----BEGIN {block_type}-----\n\n"
        + "\n".join(lines)
        + f"\n={crc_b64}\n-----END {block_type}-----\n"
    )


# ── high-level key builders ─────────────────────────────────────────────────


def _get_signing_key_obj(
    private_bytes: bytes, key_type: int, key_bits: int
):
    """Return an ecdsa SigningKey for the given key type."""
    if key_type == 1:
        return SigningKey.from_string(private_bytes, curve=Ed25519)
    curve = _ECDSA_CURVE.get((key_type, key_bits))
    if curve is not None:
        return SigningKey.from_string(private_bytes, curve=curve)
    return None  # RSA – handled separately


def _get_public_bytes(
    private_bytes: bytes, key_type: int, key_bits: int, is_encrypt: bool
):
    """Derive the public-key bytes from private-key bytes."""
    if key_type == 1 and is_encrypt:
        return x25519_public_key(private_bytes)
    if key_type == 1:
        sk = SigningKey.from_string(private_bytes, curve=Ed25519)
        return sk.get_verifying_key().to_string()
    curve = _ECDSA_CURVE.get((key_type, key_bits))
    if curve is not None:
        sk = SigningKey.from_string(private_bytes, curve=curve)
        return sk.get_verifying_key().to_string("uncompressed")
    return None


def _build_ecc_key_body(
    private_bytes: bytes,
    key_type: int,
    key_bits: int,
    is_encrypt: bool,
):
    """Build a v4 secret-key body for an ECC key.

    Returns ``(full_body, pub_body, algo)``.
    """
    pub_raw = _get_public_bytes(private_bytes, key_type, key_bits, is_encrypt)
    is_cv25519 = key_type == 1

    if is_encrypt:
        oid = _ENC_OID[(key_type, key_bits)]
        h_id, s_id = _ECDH_KDF[(key_type, key_bits)]
        kdf = _make_ecdh_kdf_params(h_id, s_id)
        pub_mat = _build_ecdh_pub_material(oid, pub_raw, kdf)
        algo = ALGO_ECDH
    else:
        oid = _SIGN_OID[(key_type, key_bits)]
        algo = _ecc_signing_algo(key_type)
        if is_cv25519:
            pub_mat = _build_eddsa_pub_material(oid, pub_raw)
        else:
            pub_mat = _build_ecdsa_pub_material(oid, pub_raw)

    # For X25519, apply clamping to the stored secret key
    sec_bytes = private_bytes
    if is_cv25519 and is_encrypt:
        sec_bytes = _clamp_x25519_secret(sec_bytes)

    sec_mat = _build_ecc_sec_material_mpi(sec_bytes, is_cv25519)
    full_body, pub_body = build_key_body(algo, pub_mat, sec_mat)
    return full_body, pub_body, algo


def _build_rsa_key_body(rsa: Dict[str, int]):
    """Returns ``(full_body, pub_body, algo)``."""
    pub_mat = _build_rsa_pub_material(rsa)
    sec_mat = _build_rsa_sec_material(rsa)
    full_body, pub_body = build_key_body(ALGO_RSA, pub_mat, sec_mat)
    return full_body, pub_body, ALGO_RSA


# ── full transferable-key export ────────────────────────────────────────────


def export_gpg_key(
    primary_private: bytes,
    subkey_privates: Dict[int, bytes],
    key_type: int,
    key_bits: int,
    uid: str = "BIP85",
    primary_rsa: Optional[Dict] = None,
    subkey_rsas: Optional[Dict[int, Dict]] = None,
) -> str:
    """Build a full ASCII-armored transferable secret key.

    Parameters
    ----------
    primary_private : bytes
        Primary-key private key material.
    subkey_privates : dict
        ``{sub_key_role: private_bytes}`` for each subkey
        (0 = encrypt, 1 = auth, 2 = sign).
    key_type, key_bits : int
        BIP85 GPG key type and size.
    uid : str
        User ID string embedded in the key.
    primary_rsa : dict, optional
        RSA key components for primary key (key_type 0 only).
    subkey_rsas : dict, optional
        ``{sub_key_role: rsa_dict}`` for RSA subkeys.

    Returns
    -------
    str – ASCII-armored PGP PRIVATE KEY BLOCK.
    """
    packets = b""
    is_rsa = key_type == 0

    # ── primary key ──────────────────────────────────────────────────────
    if is_rsa:
        primary_body, primary_pub, primary_algo = _build_rsa_key_body(primary_rsa)
    else:
        primary_body, primary_pub, primary_algo = _build_ecc_key_body(
            primary_private, key_type, key_bits, is_encrypt=False
        )
    packets += encode_packet(5, primary_body)  # tag 5 = Secret-Key

    fp = key_fingerprint_v4(primary_pub)
    kid = key_id_from_fingerprint(fp)

    # ── User ID ──────────────────────────────────────────────────────────
    uid_bytes = uid.encode("utf-8")
    packets += encode_packet(13, uid_bytes)  # tag 13 = User ID

    # ── self-certification signature ─────────────────────────────────────
    hash_algo = _SIG_HASH[(key_type, key_bits)]
    hsub = _hashed_subpackets_self_sig(GENESIS_TIMESTAMP, FLAG_CERTIFY, fp)
    msg_data = _certification_hash_data(primary_pub, uid)

    primary_sk_obj = _get_signing_key_obj(primary_private, key_type, key_bits)
    packets += build_signature_packet(
        message_data=msg_data,
        sig_type=SIG_POSITIVE_CERT,
        pub_algo=primary_algo,
        hash_algo=hash_algo,
        hashed_sub=hsub,
        key_id=kid,
        signing_key=primary_sk_obj,
        key_type=key_type,
        key_bits=key_bits,
        rsa_key=primary_rsa,
    )

    # ── subkeys ──────────────────────────────────────────────────────────
    for role in sorted(subkey_privates):
        is_enc = role == 0
        sub_priv = subkey_privates[role]
        sub_rsa = (subkey_rsas or {}).get(role)

        if is_rsa:
            sub_body, sub_pub, sub_algo = _build_rsa_key_body(sub_rsa)
        else:
            sub_body, sub_pub, sub_algo = _build_ecc_key_body(
                sub_priv, key_type, key_bits, is_encrypt=is_enc
            )
        packets += encode_packet(7, sub_body)  # tag 7 = Secret-Subkey

        # key flags
        if is_enc:
            flags = FLAG_ENCRYPT_COMM | FLAG_ENCRYPT_STOR
        elif role == 1:
            flags = FLAG_AUTHENTICATE
        else:
            flags = FLAG_SIGN

        bind_data = _binding_hash_data(primary_pub, sub_pub)
        hsub_bind = _hashed_subpackets_subkey_binding(GENESIS_TIMESTAMP, flags, fp)

        # For signing/auth subkeys, create embedded back-signature
        embedded = None
        if not is_enc:
            sub_sk_obj = _get_signing_key_obj(sub_priv, key_type, key_bits)
            back_hsub = _encode_subpacket(
                SUBPKT_CREATION_TIME, struct.pack(">I", GENESIS_TIMESTAMP)
            )
            # Build embedded primary-key-binding signature body (no packet framing)
            back_full, back_digest = _sig_hash_input(
                bind_data, SIG_PRIMARY_KEY_BINDING, sub_algo, hash_algo, back_hsub
            )
            back_sig_mpis = _do_sign(
                back_full, back_digest, sub_sk_obj, sub_algo,
                key_type, key_bits, sub_rsa,
            )
            back_unhashed = _encode_subpackets([_unhashed_subpackets(kid)])
            back_hashed_enc = _encode_subpackets([back_hsub])
            embedded = (
                bytes([4, SIG_PRIMARY_KEY_BINDING, sub_algo, hash_algo])
                + back_hashed_enc
                + back_unhashed
                + back_digest[:2]
                + back_sig_mpis
            )

        packets += build_signature_packet(
            message_data=bind_data,
            sig_type=SIG_SUBKEY_BINDING,
            pub_algo=primary_algo,
            hash_algo=hash_algo,
            hashed_sub=hsub_bind,
            key_id=kid,
            signing_key=primary_sk_obj,
            key_type=key_type,
            key_bits=key_bits,
            rsa_key=primary_rsa,
            embedded_sig=embedded,
        )

    return ascii_armor(packets)
