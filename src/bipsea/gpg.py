"""
BIP85 GPG key derivation for all OpenPGP key types.

Supports:
  key_type 0 (RSA)       – key_bits: 1024, 2048, 4096
  key_type 1 (Curve25519) – key_bits: 256 (Ed25519 sign/auth, X25519 encrypt)
  key_type 2 (secp256k1)  – key_bits: 256
  key_type 3 (NIST)       – key_bits: 256, 384, 521
  key_type 4 (Brainpool)  – key_bits: 256, 384, 512

Derivation path:
  Primary:  m/83696968'/828365'/{key_type}'/{key_bits}'/{key_index}'
  Sub-key:  m/83696968'/828365'/{key_type}'/{key_bits}'/{key_index}'/{sub_key}'
    sub_key 0' = ENCRYPTION
    sub_key 1' = AUTHENTICATION
    sub_key 2' = SIGNATURE
"""

from typing import Callable, Dict, Tuple

from Crypto.PublicKey import RSA

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

# ── constants ────────────────────────────────────────────────────────────────

KEY_TYPE_RSA = 0
KEY_TYPE_CURVE25519 = 1
KEY_TYPE_SECP256K1 = 2
KEY_TYPE_NIST = 3
KEY_TYPE_BRAINPOOL = 4

VALID_KEY_TYPES = {
    KEY_TYPE_RSA,
    KEY_TYPE_CURVE25519,
    KEY_TYPE_SECP256K1,
    KEY_TYPE_NIST,
    KEY_TYPE_BRAINPOOL,
}

VALID_KEY_BITS: Dict[int, Tuple[int, ...]] = {
    KEY_TYPE_RSA: (1024, 2048, 3072, 4096),
    KEY_TYPE_CURVE25519: (256,),
    KEY_TYPE_SECP256K1: (256,),
    KEY_TYPE_NIST: (256, 384, 521),
    KEY_TYPE_BRAINPOOL: (256, 384, 512),
}

# Mapping (key_type, key_bits) → ecdsa curve object (non-RSA only)
ECC_CURVES = {
    (KEY_TYPE_SECP256K1, 256): SECP256k1,
    (KEY_TYPE_NIST, 256): NIST256p,
    (KEY_TYPE_NIST, 384): NIST384p,
    (KEY_TYPE_NIST, 521): NIST521p,
    (KEY_TYPE_BRAINPOOL, 256): BRAINPOOLP256r1,
    (KEY_TYPE_BRAINPOOL, 384): BRAINPOOLP384r1,
    (KEY_TYPE_BRAINPOOL, 512): BRAINPOOLP512r1,
}

# Sub-key roles
SUBKEY_ENCRYPT = 0
SUBKEY_AUTH = 1
SUBKEY_SIGN = 2

# BIP85-DRNG is required when > 64 bytes of random input are needed
DRNG_REQUIRED_ECC = {(KEY_TYPE_NIST, 521)}


# ── validation ───────────────────────────────────────────────────────────────


def validate_gpg_params(key_type: int, key_bits: int):
    if key_type not in VALID_KEY_TYPES:
        raise ValueError(f"Invalid GPG key_type: {key_type}")
    valid = VALID_KEY_BITS[key_type]
    if key_bits not in valid:
        raise ValueError(
            f"Invalid key_bits {key_bits} for key_type {key_type}. "
            f"Valid values: {valid}"
        )


# ── ECC key derivation ──────────────────────────────────────────────────────


def derive_ed25519_key(entropy: bytes) -> bytes:
    """Return 32-byte Ed25519 private seed from BIP85 entropy."""
    seed = entropy[:32]
    # Validate by constructing a key (raises on invalid input)
    SigningKey.from_string(seed, curve=Ed25519)
    return seed


def derive_x25519_key(entropy: bytes) -> bytes:
    """Return 32-byte X25519 private key from BIP85 entropy.

    The clamping (clear bits 0,1,2,255; set bit 254) is applied by
    the X25519 implementation at usage time.  We store the raw seed.
    """
    return entropy[:32]


def derive_ecdsa_key(entropy: bytes, key_type: int, key_bits: int) -> bytes:
    """Derive an ECDSA private key from *entropy* for the given curve.

    For NIST P-521 (key_bits=521), *entropy* must come from a
    BIP85-DRNG read (66 bytes); all others use the 64-byte HMAC
    output directly (truncated to ``curve.baselen``).

    When the raw scalar falls outside [1, order-1] it is reduced
    modulo ``order - 1`` and incremented by one so the result is
    always in range.  This is deterministic and only changes the
    output for entropy that would previously have raised ValueError.
    """
    curve = ECC_CURVES[(key_type, key_bits)]
    key_len = curve.baselen
    raw = entropy[:key_len]
    scalar = int.from_bytes(raw, "big")
    if scalar == 0 or scalar >= curve.order:
        scalar = (scalar % (curve.order - 1)) + 1
        raw = scalar.to_bytes(key_len, "big")
    SigningKey.from_string(raw, curve=curve)
    return raw


def derive_curve25519_key(entropy: bytes, sub_key: int = None) -> bytes:
    """Return the private key bytes for a Curve25519-based GPG key.

    * Primary key and sub_keys 1 (auth), 2 (sign) → Ed25519
    * Sub_key 0 (encrypt) → X25519
    """
    if sub_key == SUBKEY_ENCRYPT:
        return derive_x25519_key(entropy)
    return derive_ed25519_key(entropy)


# ── RSA key generation (PyCryptodome, FIPS 186-4 compliant) ─────────────────


def generate_rsa_key(
    key_bits: int, randfunc: Callable[[int], bytes]
) -> Dict[str, int]:
    """Generate an RSA key deterministically from *randfunc*.

    Uses PyCryptodome's ``RSA.generate`` which implements FIPS 186-4
    compliant random Miller-Rabin witnesses (FIPS 186-4 §C.3.1),
    matching the BIP85 spec's reference implementation.

    Returns a dict with integer components: n, e, d, p, q, dp, dq, qi.
    """
    rsa = RSA.generate(key_bits, randfunc=randfunc)
    return {
        "n": rsa.n,
        "e": rsa.e,
        "d": rsa.d,
        "p": rsa.p,
        "q": rsa.q,
        "dp": rsa.d % (rsa.p - 1),
        "dq": rsa.d % (rsa.q - 1),
        "qi": pow(rsa.q, -1, rsa.p),
    }


# ── GPG key derivation entry point ──────────────────────────────────────────


def derive_gpg_key(
    entropy: bytes,
    key_type: int,
    key_bits: int,
    drng_read: Callable[[int], bytes] = None,
    sub_key: int = None,
) -> Dict:
    """Derive a GPG key from BIP85 *entropy*.

    Parameters
    ----------
    entropy : bytes
        64-byte BIP85 HMAC output.
    key_type : int
        GPG key type (0–4).
    key_bits : int
        Key size in bits.
    drng_read : callable, optional
        BIP85-DRNG read function.  Required for RSA and NIST P-521.
    sub_key : int or None
        Sub-key role (0=encrypt, 1=auth, 2=sign) or None for primary.

    Returns
    -------
    dict with ``"key_type"``, ``"key_bits"``, ``"private_key"`` (bytes),
    and optionally ``"rsa"`` (dict of RSA components).
    """
    validate_gpg_params(key_type, key_bits)

    result: Dict = {"key_type": key_type, "key_bits": key_bits}

    if key_type == KEY_TYPE_RSA:
        if drng_read is None:
            raise ValueError("RSA key generation requires a BIP85-DRNG")
        rsa = generate_rsa_key(key_bits, drng_read)
        result["rsa"] = rsa
        # "private_key" is the private exponent in big-endian bytes
        byte_len = (rsa["n"].bit_length() + 7) // 8
        result["private_key"] = rsa["d"].to_bytes(byte_len, "big")

    elif key_type == KEY_TYPE_CURVE25519:
        result["private_key"] = derive_curve25519_key(entropy, sub_key)

    elif key_type in (KEY_TYPE_SECP256K1, KEY_TYPE_NIST, KEY_TYPE_BRAINPOOL):
        if (key_type, key_bits) in DRNG_REQUIRED_ECC:
            if drng_read is None:
                raise ValueError(
                    "This curve configuration requires a BIP85-DRNG"
                )
            curve = ECC_CURVES[(key_type, key_bits)]
            raw = drng_read(curve.baselen)
            scalar = int.from_bytes(raw, "big")
            # Reduce modulo order (no bit masking – the full entropy
            # participates so the output matches PyCryptodome / SeedSigner).
            scalar = scalar % curve.order
            if scalar == 0:
                scalar = 1  # astronomically unlikely
            raw = scalar.to_bytes(curve.baselen, "big")
            result["private_key"] = raw
        else:
            result["private_key"] = derive_ecdsa_key(
                entropy, key_type, key_bits
            )
    else:
        raise ValueError(f"Unsupported key_type: {key_type}")

    return result
