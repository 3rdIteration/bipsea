"""
Pure Python OpenPGP key generation for BIP85 GPG application (828365').

Supports key types:
  0 - RSA (1024, 2048, 4096)
  1 - Curve25519 (Ed25519 / X25519)
  2 - secp256k1
  3 - NIST (P-256, P-384, P-521)
  4 - Brainpool (brainpoolP256r1, brainpoolP384r1, brainpoolP512r1)

Outputs ASCII-armored transferable secret keys importable into GnuPG2.
"""

import base64
import hashlib
import math
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

# Bitcoin genesis block timestamp
GENESIS_TIMESTAMP = 1231006505

# OpenPGP public-key algorithm IDs
PK_ALGO_RSA = 1
PK_ALGO_ECDH = 18
PK_ALGO_ECDSA = 19
PK_ALGO_EDDSA = 22

# OpenPGP hash algorithm IDs
HASH_SHA256 = 8
HASH_SHA384 = 9
HASH_SHA512 = 10

# OpenPGP symmetric algorithm IDs
SYM_AES128 = 7
SYM_AES192 = 8
SYM_AES256 = 9

# OpenPGP signature types
SIG_POSITIVE_CERT = 0x13
SIG_SUBKEY_BINDING = 0x18
SIG_PRIMARY_KEY_BINDING = 0x19

# Key flags
FLAG_CERTIFY = 0x01
FLAG_SIGN = 0x02
FLAG_ENCRYPT_COMMS = 0x04
FLAG_ENCRYPT_STORAGE = 0x08
FLAG_AUTHENTICATE = 0x20

# BIP85 GPG application number
GPG_APP_CODE = "828365'"

# Key type definitions
GPG_KEY_TYPES = {
    0: "RSA",
    1: "Curve25519",
    2: "secp256k1",
    3: "NIST",
    4: "Brainpool",
}

GPG_VALID_KEY_BITS = {
    0: (1024, 2048, 4096),
    1: (256,),
    2: (256,),
    3: (256, 384, 521),
    4: (256, 384, 512),
}

# Curve OIDs (DER-encoded, without the length prefix)
OID_ED25519 = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
OID_CURVE25519 = bytes(
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]
)
OID_SECP256K1 = bytes([0x2B, 0x81, 0x04, 0x00, 0x0A])
OID_NIST_P256 = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
OID_NIST_P384 = bytes([0x2B, 0x81, 0x04, 0x00, 0x22])
OID_NIST_P521 = bytes([0x2B, 0x81, 0x04, 0x00, 0x23])
OID_BRAINPOOL_P256R1 = bytes(
    [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]
)
OID_BRAINPOOL_P384R1 = bytes(
    [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B]
)
OID_BRAINPOOL_P512R1 = bytes(
    [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D]
)

# DER-encoded DigestInfo prefixes for PKCS#1 v1.5 signatures
DIGEST_INFO_SHA256 = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
DIGEST_INFO_SHA384 = bytes.fromhex(
    "3041300d060960864801650304020205000430"
)
DIGEST_INFO_SHA512 = bytes.fromhex(
    "3051300d060960864801650304020305000440"
)


# ---------------------------------------------------------------------------
# X25519 pure Python implementation (RFC 7748)
# ---------------------------------------------------------------------------

_X25519_P = (1 << 255) - 19
_X25519_A24 = 121665


def _x25519_clamp(k_bytes: bytes) -> int:
    k = bytearray(k_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _x25519_scalar_mult(k_scalar: int, u: int) -> int:
    p = _X25519_P
    a24 = _X25519_A24
    x_1 = u
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k_scalar >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        A = (x_2 + z_2) % p
        AA = (A * A) % p
        B = (x_2 - z_2) % p
        BB = (B * B) % p
        E = (AA - BB) % p
        C = (x_3 + z_3) % p
        D = (x_3 - z_3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x_3 = pow(DA + CB, 2, p)
        z_3 = (x_1 * pow(DA - CB, 2, p)) % p
        x_2 = (AA * BB) % p
        z_2 = (E * (AA + a24 * E)) % p

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    return (x_2 * pow(z_2, p - 2, p)) % p


def x25519_public_key(private_key_bytes: bytes) -> bytes:
    """Derive X25519 public key from 32-byte private key."""
    k = _x25519_clamp(private_key_bytes)
    u_result = _x25519_scalar_mult(k, 9)  # base point u=9
    return u_result.to_bytes(32, "little")


# ---------------------------------------------------------------------------
# RSA key generation (pure Python)
# ---------------------------------------------------------------------------


def _is_probable_prime(n: int, randfunc: Callable, rounds: int = 28) -> bool:
    """Miller-Rabin primality test using deterministic witnesses from randfunc."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Small prime divisors check
    small_primes = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
        59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
    ]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    byte_len = (n.bit_length() + 7) // 8
    for _ in range(rounds):
        raw = randfunc(byte_len)
        a = int.from_bytes(raw, "big") % (n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_probable_prime(bits: int, randfunc: Callable) -> int:
    """Generate a probable prime of the given bit size using randfunc."""
    byte_len = (bits + 7) // 8
    while True:
        raw = randfunc(byte_len)
        n = int.from_bytes(raw, "big")
        # Ensure correct bit length: set top bit
        n |= 1 << (bits - 1)
        # Clear bits above target size
        n &= (1 << bits) - 1
        # Ensure top bit is still set
        n |= 1 << (bits - 1)
        # Make odd
        n |= 1
        if _is_probable_prime(n, randfunc):
            return n


def generate_rsa_key(
    key_bits: int, randfunc: Callable
) -> Tuple[int, int, int, int, int, int]:
    """Generate RSA key: returns (n, e, d, p, q, u) where u = p^-1 mod q."""
    e = 65537
    half = key_bits // 2
    while True:
        p = _generate_probable_prime(half, randfunc)
        q = _generate_probable_prime(half, randfunc)
        if p == q:
            continue
        # Ensure p < q (OpenPGP convention)
        if p > q:
            p, q = q, p
        n = p * q
        if n.bit_length() != key_bits:
            continue
        phi_n = (p - 1) * (q - 1)
        if math.gcd(e, phi_n) != 1:
            continue
        d = pow(e, -1, phi_n)
        u = pow(p, -1, q)
        return (n, e, d, p, q, u)


# ---------------------------------------------------------------------------
# OpenPGP packet encoding helpers
# ---------------------------------------------------------------------------


def _encode_mpi(value: int) -> bytes:
    """Encode an integer as an OpenPGP MPI (Multi-Precision Integer)."""
    if value == 0:
        return b"\x00\x00"
    bit_length = value.bit_length()
    byte_length = (bit_length + 7) // 8
    data = value.to_bytes(byte_length, "big")
    return struct.pack(">H", bit_length) + data


def _encode_mpi_bytes(data: bytes) -> bytes:
    """Encode raw bytes as an OpenPGP MPI (strip leading zeros, compute bit length)."""
    stripped = data.lstrip(b"\x00")
    if not stripped:
        return b"\x00\x00"
    bit_length = (len(stripped) - 1) * 8 + stripped[0].bit_length()
    return struct.pack(">H", bit_length) + stripped


def _packet_header(tag: int, body_length: int) -> bytes:
    """Create an OpenPGP new-format packet header."""
    # Use old-format packets for maximum compatibility
    if body_length < 256:
        return bytes([0x80 | (tag << 2) | 0]) + struct.pack("B", body_length)
    elif body_length < 65536:
        return bytes([0x80 | (tag << 2) | 1]) + struct.pack(">H", body_length)
    else:
        return bytes([0x80 | (tag << 2) | 2]) + struct.pack(">I", body_length)


def _make_packet(tag: int, body: bytes) -> bytes:
    """Create a complete OpenPGP packet (header + body)."""
    return _packet_header(tag, len(body)) + body


def _subpacket(subtype: int, data: bytes) -> bytes:
    """Create an OpenPGP signature subpacket."""
    total_len = 1 + len(data)
    if total_len < 192:
        return bytes([total_len]) + bytes([subtype]) + data
    elif total_len < 16320:
        adjusted = total_len - 192
        return (
            bytes([((adjusted >> 8) + 192) & 0xFF, adjusted & 0xFF])
            + bytes([subtype])
            + data
        )
    else:
        return (
            bytes([0xFF])
            + struct.pack(">I", total_len)
            + bytes([subtype])
            + data
        )


def _sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def _hash_for_algo(algo_id: int) -> Callable:
    if algo_id == HASH_SHA256:
        return hashlib.sha256
    elif algo_id == HASH_SHA384:
        return hashlib.sha384
    elif algo_id == HASH_SHA512:
        return hashlib.sha512
    raise ValueError(f"Unsupported hash algorithm: {algo_id}")


# ---------------------------------------------------------------------------
# Key material generation per key type
# ---------------------------------------------------------------------------


def _get_ecdsa_curve(key_type: int, key_bits: int):
    """Return the ecdsa library curve object for the given key_type and key_bits."""
    if key_type == 2:
        return SECP256k1
    elif key_type == 3:
        if key_bits == 256:
            return NIST256p
        elif key_bits == 384:
            return NIST384p
        elif key_bits == 521:
            return NIST521p
    elif key_type == 4:
        if key_bits == 256:
            return BRAINPOOLP256r1
        elif key_bits == 384:
            return BRAINPOOLP384r1
        elif key_bits == 512:
            return BRAINPOOLP512r1
    raise ValueError(f"Unsupported key_type={key_type} key_bits={key_bits}")


def _get_curve_oid(key_type: int, key_bits: int, encrypt: bool = False) -> bytes:
    """Return the OID bytes for the given curve."""
    if key_type == 1:
        return OID_CURVE25519 if encrypt else OID_ED25519
    elif key_type == 2:
        return OID_SECP256K1
    elif key_type == 3:
        if key_bits == 256:
            return OID_NIST_P256
        elif key_bits == 384:
            return OID_NIST_P384
        elif key_bits == 521:
            return OID_NIST_P521
    elif key_type == 4:
        if key_bits == 256:
            return OID_BRAINPOOL_P256R1
        elif key_bits == 384:
            return OID_BRAINPOOL_P384R1
        elif key_bits == 512:
            return OID_BRAINPOOL_P512R1
    raise ValueError(f"Unsupported key_type={key_type} key_bits={key_bits}")


def _get_kdf_params(key_bits: int) -> bytes:
    """Return ECDH KDF parameters based on key size."""
    if key_bits <= 256:
        return bytes([0x03, 0x01, HASH_SHA256, SYM_AES128])
    elif key_bits <= 384:
        return bytes([0x03, 0x01, HASH_SHA384, SYM_AES192])
    else:
        return bytes([0x03, 0x01, HASH_SHA512, SYM_AES256])


def _get_hash_algo(key_type: int, key_bits: int) -> int:
    """Return the hash algorithm ID for signatures based on key parameters."""
    if key_type == 0:
        if key_bits <= 2048:
            return HASH_SHA256
        return HASH_SHA512
    if key_type == 1:
        return HASH_SHA256
    if key_bits <= 256:
        return HASH_SHA256
    elif key_bits <= 384:
        return HASH_SHA384
    return HASH_SHA512


def _scalar_byte_len(key_type: int, key_bits: int) -> int:
    """Return the byte length of the private scalar for ECC key types."""
    if key_type == 1:
        return 32
    if key_type == 2:
        return 32
    if key_type == 3:
        if key_bits == 256:
            return 32
        elif key_bits == 384:
            return 48
        elif key_bits == 521:
            return 66
    if key_type == 4:
        if key_bits == 256:
            return 32
        elif key_bits == 384:
            return 48
        elif key_bits == 512:
            return 64
    raise ValueError(f"Unsupported key_type={key_type} key_bits={key_bits}")


def _needs_drng(key_type: int, key_bits: int) -> bool:
    """Check if DRNG is needed (entropy > 64 bytes)."""
    if key_type == 0:
        return True
    if key_type == 3 and key_bits == 521:
        return True
    return False


class _KeyMaterial:
    """Container for OpenPGP key material."""

    def __init__(
        self,
        algo: int,
        public_body: bytes,
        secret_body: bytes,
        sign_func: Optional[Callable] = None,
    ):
        self.algo = algo
        self.public_body = public_body
        self.secret_body = secret_body
        self.sign_func = sign_func


def _generate_rsa_material(
    entropy: bytes, key_bits: int, randfunc: Callable
) -> _KeyMaterial:
    """Generate RSA key material from DRNG-seeded random."""
    n, e, d, p, q, u = generate_rsa_key(key_bits, randfunc)

    public_body = _encode_mpi(n) + _encode_mpi(e)
    secret_body = _encode_mpi(d) + _encode_mpi(p) + _encode_mpi(q) + _encode_mpi(u)

    def sign_func(hash_value: bytes, hash_algo: int) -> bytes:
        return _rsa_pkcs1_sign(hash_value, hash_algo, d, n)

    return _KeyMaterial(PK_ALGO_RSA, public_body, secret_body, sign_func)


def _rsa_pkcs1_sign(hash_value: bytes, hash_algo: int, d: int, n: int) -> bytes:
    """PKCS#1 v1.5 RSA signature."""
    if hash_algo == HASH_SHA256:
        digest_info = DIGEST_INFO_SHA256
    elif hash_algo == HASH_SHA384:
        digest_info = DIGEST_INFO_SHA384
    elif hash_algo == HASH_SHA512:
        digest_info = DIGEST_INFO_SHA512
    else:
        raise ValueError(f"Unsupported hash algo for RSA: {hash_algo}")

    em_len = (n.bit_length() + 7) // 8
    t = digest_info + hash_value
    ps_len = em_len - len(t) - 3
    if ps_len < 8:
        raise ValueError("RSA key too short for this signature")
    em = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t
    m = int.from_bytes(em, "big")
    s = pow(m, d, n)
    return _encode_mpi(s)


def _generate_ed25519_material(entropy: bytes) -> _KeyMaterial:
    """Generate Ed25519 key material."""
    seed = entropy[:32]
    sk = SigningKey.from_string(seed, curve=Ed25519)
    vk = sk.get_verifying_key()
    pub_bytes = vk.to_string()

    # OpenPGP EdDSA: OID + MPI(0x40 || native 32-byte key)
    oid = OID_ED25519
    public_point = b"\x40" + pub_bytes
    public_body = bytes([len(oid)]) + oid + _encode_mpi_bytes(public_point)
    secret_body = _encode_mpi_bytes(seed)

    def sign_func(hash_value: bytes, hash_algo: int) -> bytes:
        # Ed25519 signs the hash value directly (not double-hashed)
        sig = sk.sign_deterministic(hash_value)
        # Split into r and s (each 32 bytes)
        r_bytes = sig[:32]
        s_bytes = sig[32:]
        return _encode_mpi_bytes(r_bytes) + _encode_mpi_bytes(s_bytes)

    return _KeyMaterial(PK_ALGO_EDDSA, public_body, secret_body, sign_func)


def _generate_x25519_material(entropy: bytes) -> _KeyMaterial:
    """Generate X25519 (Curve25519 ECDH) key material."""
    secret = entropy[:32]
    pub_bytes = x25519_public_key(secret)

    # OpenPGP ECDH: OID + MPI(0x40 || native 32-byte key) + KDF params
    oid = OID_CURVE25519
    public_point = b"\x40" + pub_bytes
    kdf_params = _get_kdf_params(256)
    public_body = (
        bytes([len(oid)]) + oid + _encode_mpi_bytes(public_point) + kdf_params
    )
    # GnuPG stores Curve25519 private key clamped and reversed (LE→BE) as MPI
    clamped = bytearray(secret)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    secret_be = bytes(reversed(clamped))
    secret_body = _encode_mpi_bytes(secret_be)

    return _KeyMaterial(PK_ALGO_ECDH, public_body, secret_body)


def _generate_ecdsa_material(
    entropy: bytes, key_type: int, key_bits: int, randfunc: Optional[Callable] = None
) -> _KeyMaterial:
    """Generate ECDSA key material for signing capabilities."""
    curve = _get_ecdsa_curve(key_type, key_bits)
    scalar_len = _scalar_byte_len(key_type, key_bits)

    if _needs_drng(key_type, key_bits) and randfunc is not None:
        secret_bytes = randfunc(scalar_len)
    else:
        secret_bytes = entropy[:scalar_len]

    # Ensure scalar is in valid range for the curve
    scalar_int = int.from_bytes(secret_bytes, "big") % curve.order
    if scalar_int == 0:
        scalar_int = 1
    secret_bytes = scalar_int.to_bytes(scalar_len, "big")

    sk = SigningKey.from_string(secret_bytes, curve=curve)
    vk = sk.get_verifying_key()
    # Uncompressed point: 0x04 || x || y
    pub_uncompressed = b"\x04" + vk.to_string()

    oid = _get_curve_oid(key_type, key_bits)
    public_body = bytes([len(oid)]) + oid + _encode_mpi_bytes(pub_uncompressed)
    secret_body = _encode_mpi(scalar_int)

    hash_algo = _get_hash_algo(key_type, key_bits)

    def sign_func(hash_value: bytes, hash_algo_id: int) -> bytes:
        hf = _hash_for_algo(hash_algo_id)
        # sign_digest_deterministic takes a pre-computed hash
        sig_bytes = sk.sign_digest_deterministic(hash_value, hashfunc=hf)
        r_len = len(sig_bytes) // 2
        r = int.from_bytes(sig_bytes[:r_len], "big")
        s = int.from_bytes(sig_bytes[r_len:], "big")
        return _encode_mpi(r) + _encode_mpi(s)

    return _KeyMaterial(PK_ALGO_ECDSA, public_body, secret_body, sign_func)


def _generate_ecdh_material(
    entropy: bytes, key_type: int, key_bits: int, randfunc: Optional[Callable] = None
) -> _KeyMaterial:
    """Generate ECDH key material for encryption capability."""
    if key_type == 1:
        return _generate_x25519_material(entropy)

    curve = _get_ecdsa_curve(key_type, key_bits)
    scalar_len = _scalar_byte_len(key_type, key_bits)

    if _needs_drng(key_type, key_bits) and randfunc is not None:
        secret_bytes = randfunc(scalar_len)
    else:
        secret_bytes = entropy[:scalar_len]

    scalar_int = int.from_bytes(secret_bytes, "big") % curve.order
    if scalar_int == 0:
        scalar_int = 1
    secret_bytes = scalar_int.to_bytes(scalar_len, "big")

    sk = SigningKey.from_string(secret_bytes, curve=curve)
    vk = sk.get_verifying_key()
    pub_uncompressed = b"\x04" + vk.to_string()

    oid = _get_curve_oid(key_type, key_bits, encrypt=True)
    kdf_params = _get_kdf_params(key_bits)
    public_body = (
        bytes([len(oid)]) + oid + _encode_mpi_bytes(pub_uncompressed) + kdf_params
    )
    secret_body = _encode_mpi(scalar_int)

    return _KeyMaterial(PK_ALGO_ECDH, public_body, secret_body)


# ---------------------------------------------------------------------------
# OpenPGP key packet construction
# ---------------------------------------------------------------------------


def _key_packet_body(material: _KeyMaterial, timestamp: int) -> bytes:
    """Build the public portion of a key packet body (v4)."""
    body = b""
    body += bytes([4])  # version
    body += struct.pack(">I", timestamp)  # creation time
    body += bytes([material.algo])  # algorithm
    body += material.public_body  # public key material
    return body


def _secret_key_packet_body(material: _KeyMaterial, timestamp: int) -> bytes:
    """Build a full secret key packet body (v4, unprotected)."""
    pub = _key_packet_body(material, timestamp)
    # S2K usage: 0 = unprotected
    sec = bytes([0])
    sec += material.secret_body
    # Two-octet checksum: sum of all secret key material bytes mod 65536
    checksum = sum(material.secret_body) & 0xFFFF
    sec += struct.pack(">H", checksum)
    return pub + sec


def _key_fingerprint(pub_body: bytes) -> bytes:
    """Compute v4 key fingerprint: SHA-1(0x99 || len || pub_body)."""
    prefix = b"\x99" + struct.pack(">H", len(pub_body))
    return _sha1(prefix + pub_body)


def _key_id(fingerprint: bytes) -> bytes:
    """Return the 8-byte key ID (last 8 bytes of fingerprint)."""
    return fingerprint[-8:]


# ---------------------------------------------------------------------------
# Signature construction
# ---------------------------------------------------------------------------


def _make_signature(
    sig_type: int,
    pk_algo: int,
    hash_algo: int,
    hashed_subpackets: bytes,
    unhashed_subpackets: bytes,
    hash_data: bytes,
    sign_func: Callable,
) -> bytes:
    """Construct a v4 signature packet body."""
    # Signature header
    sig_header = b""
    sig_header += bytes([4])  # version
    sig_header += bytes([sig_type])
    sig_header += bytes([pk_algo])
    sig_header += bytes([hash_algo])
    sig_header += struct.pack(">H", len(hashed_subpackets))
    sig_header += hashed_subpackets

    # Compute hash
    h = _hash_for_algo(hash_algo)()
    h.update(hash_data)
    h.update(sig_header)
    # Trailer: version (4), 0xFF, 4-byte length of sig_header
    trailer = bytes([4, 0xFF]) + struct.pack(">I", len(sig_header))
    h.update(trailer)
    hash_value = h.digest()

    # Left 16 bits of hash
    left16 = hash_value[:2]

    # Compute signature
    sig_mpis = sign_func(hash_value, hash_algo)

    # Build signature body
    body = sig_header
    body += struct.pack(">H", len(unhashed_subpackets))
    body += unhashed_subpackets
    body += left16
    body += sig_mpis

    return body


def _hash_key_for_sig(pub_body: bytes) -> bytes:
    """Hash material for a key in a signature: 0x99 || len || pub_body."""
    return b"\x99" + struct.pack(">H", len(pub_body)) + pub_body


def _hash_uid_for_sig(uid: str) -> bytes:
    """Hash material for a user ID in a signature: 0xB4 || len || uid_bytes."""
    uid_bytes = uid.encode("utf-8")
    return b"\xB4" + struct.pack(">I", len(uid_bytes)) + uid_bytes


def _make_certification_sig(
    primary_pub_body: bytes,
    uid: str,
    primary_material: _KeyMaterial,
    primary_fp: bytes,
    hash_algo: int,
    key_flags: int,
) -> bytes:
    """Create a positive certification signature (type 0x13) on a UID."""
    # Hashed subpackets
    hashed = b""
    # Signature creation time (type 2)
    hashed += _subpacket(2, struct.pack(">I", GENESIS_TIMESTAMP))
    # Key flags (type 27)
    hashed += _subpacket(27, bytes([key_flags]))
    # Issuer fingerprint (type 33) - critical
    hashed += _subpacket(33, bytes([4]) + primary_fp)
    # Preferred symmetric algorithms (type 11)
    hashed += _subpacket(11, bytes([SYM_AES256, SYM_AES192, SYM_AES128]))
    # Preferred hash algorithms (type 21)
    hashed += _subpacket(21, bytes([HASH_SHA512, HASH_SHA384, HASH_SHA256]))
    # Features: MDC (type 30)
    hashed += _subpacket(30, bytes([0x01]))

    # Unhashed subpackets
    unhashed = b""
    # Issuer key ID (type 16)
    unhashed += _subpacket(16, _key_id(primary_fp))

    # Hash data: key || uid
    hash_data = _hash_key_for_sig(primary_pub_body)
    hash_data += _hash_uid_for_sig(uid)

    sig_body = _make_signature(
        SIG_POSITIVE_CERT,
        primary_material.algo,
        hash_algo,
        hashed,
        unhashed,
        hash_data,
        primary_material.sign_func,
    )
    return _make_packet(2, sig_body)


def _make_subkey_binding_sig(
    primary_pub_body: bytes,
    sub_pub_body: bytes,
    primary_material: _KeyMaterial,
    primary_fp: bytes,
    hash_algo: int,
    key_flags: int,
    sub_material: Optional[_KeyMaterial] = None,
) -> bytes:
    """Create a subkey binding signature (type 0x18)."""
    # Hashed subpackets
    hashed = b""
    # Signature creation time (type 2)
    hashed += _subpacket(2, struct.pack(">I", GENESIS_TIMESTAMP))
    # Key flags (type 27)
    hashed += _subpacket(27, bytes([key_flags]))
    # Issuer fingerprint (type 33)
    hashed += _subpacket(33, bytes([4]) + primary_fp)

    # For signing-capable subkeys, embed a primary key binding back-signature
    if key_flags & (FLAG_SIGN | FLAG_AUTHENTICATE) and sub_material is not None:
        if sub_material.sign_func is not None:
            back_sig = _make_primary_binding_sig(
                primary_pub_body,
                sub_pub_body,
                sub_material,
                hash_algo,
                primary_fp,
            )
            # Embedded signature subpacket (type 32)
            hashed += _subpacket(32, back_sig)

    # Unhashed subpackets
    unhashed = b""
    unhashed += _subpacket(16, _key_id(primary_fp))

    # Hash data: primary key || subkey
    hash_data = _hash_key_for_sig(primary_pub_body)
    hash_data += _hash_key_for_sig(sub_pub_body)

    sig_body = _make_signature(
        SIG_SUBKEY_BINDING,
        primary_material.algo,
        hash_algo,
        hashed,
        unhashed,
        hash_data,
        primary_material.sign_func,
    )
    return _make_packet(2, sig_body)


def _make_primary_binding_sig(
    primary_pub_body: bytes,
    sub_pub_body: bytes,
    sub_material: _KeyMaterial,
    hash_algo: int,
    primary_fp: bytes,
) -> bytes:
    """Create a primary key binding back-signature (type 0x19) - returned as raw body."""
    hashed = b""
    hashed += _subpacket(2, struct.pack(">I", GENESIS_TIMESTAMP))
    hashed += _subpacket(33, bytes([4]) + primary_fp)

    unhashed = b""
    unhashed += _subpacket(16, _key_id(primary_fp))

    hash_data = _hash_key_for_sig(primary_pub_body)
    hash_data += _hash_key_for_sig(sub_pub_body)

    return _make_signature(
        SIG_PRIMARY_KEY_BINDING,
        sub_material.algo,
        hash_algo,
        hashed,
        unhashed,
        hash_data,
        sub_material.sign_func,
    )


# ---------------------------------------------------------------------------
# ASCII armor
# ---------------------------------------------------------------------------


def _ascii_armor(data: bytes, block_type: str = "PGP PRIVATE KEY BLOCK") -> str:
    """ASCII-armor OpenPGP data."""
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i : i + 76] for i in range(0, len(b64), 76)]

    # CRC24
    crc = _crc24(data)
    crc_b64 = base64.b64encode(crc.to_bytes(3, "big")).decode("ascii")

    result = f"-----BEGIN {block_type}-----\n"
    result += "\n"
    result += "\n".join(lines) + "\n"
    result += f"={crc_b64}\n"
    result += f"-----END {block_type}-----\n"
    return result


def _crc24(data: bytes) -> int:
    """Compute CRC-24 per OpenPGP."""
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


# ---------------------------------------------------------------------------
# Main GPG key generation function
# ---------------------------------------------------------------------------


def generate_gpg_key_material(
    entropy: bytes,
    key_type: int,
    key_bits: int,
    capability: str,
    randfunc: Optional[Callable] = None,
) -> _KeyMaterial:
    """Generate key material for a specific capability.

    capability is one of: 'certify', 'sign', 'encrypt', 'authenticate'
    """
    if key_type == 0:
        return _generate_rsa_material(entropy, key_bits, randfunc)
    elif key_type == 1:
        if capability == "encrypt":
            return _generate_x25519_material(entropy)
        else:
            return _generate_ed25519_material(entropy)
    else:
        # secp256k1, NIST, Brainpool
        if capability == "encrypt":
            return _generate_ecdh_material(entropy, key_type, key_bits, randfunc)
        else:
            return _generate_ecdsa_material(entropy, key_type, key_bits, randfunc)


def build_gpg_key(
    primary_material: _KeyMaterial,
    sub_materials: List[Tuple[_KeyMaterial, int]],
    uid: str,
    key_type: int,
    key_bits: int,
) -> str:
    """Build a complete ASCII-armored transferable secret key.

    primary_material: _KeyMaterial for the primary (certify) key
    sub_materials: list of (_KeyMaterial, key_flags) for each subkey
    uid: user ID string
    key_type: GPG key type (0-4)
    key_bits: key size in bits

    Returns ASCII-armored string.
    """
    timestamp = GENESIS_TIMESTAMP
    hash_algo = _get_hash_algo(key_type, key_bits)

    # Build primary secret key packet
    primary_sec_body = _secret_key_packet_body(primary_material, timestamp)
    primary_pub_body = _key_packet_body(primary_material, timestamp)
    primary_fp = _key_fingerprint(primary_pub_body)

    packets = b""
    # Secret key packet (tag 5)
    packets += _make_packet(5, primary_sec_body)

    # User ID packet (tag 13)
    uid_bytes = uid.encode("utf-8")
    packets += _make_packet(13, uid_bytes)

    # Self-certification signature
    packets += _make_certification_sig(
        primary_pub_body,
        uid,
        primary_material,
        primary_fp,
        hash_algo,
        FLAG_CERTIFY,
    )

    # Subkeys
    for sub_material, sub_flags in sub_materials:
        sub_sec_body = _secret_key_packet_body(sub_material, timestamp)
        sub_pub_body = _key_packet_body(sub_material, timestamp)

        # Secret subkey packet (tag 7)
        packets += _make_packet(7, sub_sec_body)

        # Subkey binding signature
        packets += _make_subkey_binding_sig(
            primary_pub_body,
            sub_pub_body,
            primary_material,
            primary_fp,
            hash_algo,
            sub_flags,
            sub_material if sub_flags & (FLAG_SIGN | FLAG_AUTHENTICATE) else None,
        )

    return _ascii_armor(packets)


def validate_gpg_params(key_type: int, key_bits: int):
    """Validate GPG key type and key bits."""
    if key_type not in GPG_KEY_TYPES:
        raise ValueError(
            f"Unsupported key_type={key_type}. Must be one of {list(GPG_KEY_TYPES.keys())}"
        )
    valid = GPG_VALID_KEY_BITS[key_type]
    if key_bits not in valid:
        raise ValueError(
            f"key_bits={key_bits} invalid for key_type={key_type} ({GPG_KEY_TYPES[key_type]}). "
            f"Must be one of {valid}"
        )
