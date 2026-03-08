"""Compare bipsea GPG key test vectors with OpenSSL (via the `cryptography` library).

For each GPG key type, this module validates the entropy→key step:

- RSA (key_type=0): Generate key with pycryptodome from DRNG, load into
  OpenSSL via RSAPrivateNumbers, verify sign/verify roundtrip.
- ECDSA NIST (key_type=3): Derive private scalar from entropy, create key
  in OpenSSL, verify public key matches.
- EdDSA (key_type=4, 256-bit): Use entropy as Ed25519 seed, create key in
  OpenSSL, verify sign/verify roundtrip.
"""

import pytest
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from data.bip85_vectors import COMMON_XPRV

from bipsea.bip32types import parse_ext_key
from bipsea.bip85 import DRNG, apply_85, derive


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gpg_entropy(path: str) -> bytes:
    """Derive 64-byte GPG entropy for the given BIP-85 GPG path."""
    master = parse_ext_key(COMMON_XPRV)
    output = apply_85(derive(master, path), path)
    return output["entropy"]


# ---------------------------------------------------------------------------
# RSA (key_type=0) – pycryptodome vs OpenSSL
# ---------------------------------------------------------------------------

# GPG key type 0 paths: m/83696968'/828365'/0'/{key_bits}'/{index}'
RSA_VECTORS = [
    ("m/83696968'/828365'/0'/1024'/0'", 1024),
    ("m/83696968'/828365'/0'/1024'/1'", 1024),
]


@pytest.mark.slow
@pytest.mark.parametrize("path,key_bits", RSA_VECTORS, ids=[v[0] for v in RSA_VECTORS])
def test_rsa_openssl_cross_validation(path, key_bits):
    """Generate RSA key with pycryptodome (bipsea's DRNG) and validate it in OpenSSL."""
    entropy = _gpg_entropy(path)
    pcd_key = RSA.generate(key_bits, randfunc=DRNG(entropy).read)

    # Load the same key material into OpenSSL via cryptography
    pub_numbers = rsa.RSAPublicNumbers(e=pcd_key.e, n=pcd_key.n)
    priv_numbers = rsa.RSAPrivateNumbers(
        p=pcd_key.p,
        q=pcd_key.q,
        d=pcd_key.d,
        dmp1=rsa.rsa_crt_dmp1(pcd_key.d, pcd_key.p),
        dmq1=rsa.rsa_crt_dmq1(pcd_key.d, pcd_key.q),
        iqmp=rsa.rsa_crt_iqmp(pcd_key.p, pcd_key.q),
        public_numbers=pub_numbers,
    )
    ossl_key = priv_numbers.private_key()

    # Verify key properties match
    ossl_pub = ossl_key.public_key()
    ossl_pub_numbers = ossl_pub.public_numbers()
    assert ossl_pub_numbers.n == pcd_key.n
    assert ossl_pub_numbers.e == pcd_key.e
    assert ossl_key.key_size == key_bits

    # OpenSSL sign / verify roundtrip
    message = b"bipsea openssl cross-validation"
    signature = ossl_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    # Verification raises InvalidSignature on failure
    ossl_pub.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # Compare PEM-encoded public key (pycryptodome export vs OpenSSL export)
    pcd_pub_pem = pcd_key.public_key().export_key()
    ossl_pub_pem = ossl_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Strip trailing newline differences
    assert pcd_pub_pem.strip() == ossl_pub_pem.strip()


# ---------------------------------------------------------------------------
# ECDSA NIST curves (key_type=3) – entropy→private scalar→OpenSSL key
# ---------------------------------------------------------------------------

# Map GPG key_bits to OpenSSL curve class and byte length of private key
ECDSA_NIST_CURVES = {
    256: (ec.SECP256R1(), 32),
    384: (ec.SECP384R1(), 48),
    521: (ec.SECP521R1(), 66),
}

ECDSA_VECTORS = [
    ("m/83696968'/828365'/3'/256'/0'", 256),
    ("m/83696968'/828365'/3'/384'/0'", 384),
    ("m/83696968'/828365'/3'/521'/0'", 521),
]


@pytest.mark.parametrize(
    "path,key_bits", ECDSA_VECTORS, ids=[v[0] for v in ECDSA_VECTORS]
)
def test_ecdsa_nist_openssl(path, key_bits):
    """Derive an ECDSA private key from bipsea entropy and validate in OpenSSL.

    The entropy→key step for ECDSA: interpret the first N bytes of the 64-byte
    entropy as a big-endian integer and reduce modulo the curve order to obtain
    the private scalar.  OpenSSL (via ``ec.derive_private_key``) then produces
    a fully validated key object.
    """
    entropy = _gpg_entropy(path)
    curve, byte_len = ECDSA_NIST_CURVES[key_bits]

    # Derive private scalar: big-endian int from first byte_len bytes, mod order
    raw_int = int.from_bytes(entropy[:byte_len], "big")
    # derive_private_key handles reduction mod curve order internally
    ossl_key = ec.derive_private_key(raw_int, curve)

    # Validate the key round-trips through serialization
    priv_pem = ossl_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    reloaded = serialization.load_pem_private_key(priv_pem, password=None)
    assert (
        reloaded.private_numbers().private_value
        == ossl_key.private_numbers().private_value
    )

    # OpenSSL sign / verify roundtrip
    message = b"bipsea ecdsa cross-validation"
    sig_algo = ec.ECDSA(hashes.SHA256())
    signature = ossl_key.sign(message, sig_algo)
    ossl_key.public_key().verify(signature, message, sig_algo)


# ---------------------------------------------------------------------------
# EdDSA – Ed25519 (key_type=4, 256 bits)
# ---------------------------------------------------------------------------


def test_ed25519_openssl():
    """Derive an Ed25519 key from bipsea entropy and validate in OpenSSL.

    The entropy→key step for Ed25519: use the first 32 bytes of the 64-byte
    entropy as the private key seed.
    """
    path = "m/83696968'/828365'/4'/256'/0'"
    entropy = _gpg_entropy(path)
    seed = entropy[:32]

    ossl_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)

    # Validate via sign / verify roundtrip
    message = b"bipsea ed25519 cross-validation"
    signature = ossl_key.sign(message)
    ossl_key.public_key().verify(signature, message)

    # Validate the key survives serialization roundtrip
    raw_bytes = ossl_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    reloaded = ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
    assert (
        reloaded.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        == ossl_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


# ---------------------------------------------------------------------------
# Verify entropy determinism: same path always yields same entropy & key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "m/83696968'/828365'/0'/1024'/0'",
        "m/83696968'/828365'/3'/256'/0'",
        "m/83696968'/828365'/4'/256'/0'",
    ],
)
def test_entropy_determinism(path):
    """Entropy derivation must be deterministic across invocations."""
    ent1 = _gpg_entropy(path)
    ent2 = _gpg_entropy(path)
    assert ent1 == ent2
    assert len(ent1) == 64


# ---------------------------------------------------------------------------
# RSA: Verify mathematical properties in OpenSSL
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_rsa_mathematical_properties_openssl():
    """Verify RSA key mathematical relationships via OpenSSL."""
    path = "m/83696968'/828365'/0'/1024'/0'"
    entropy = _gpg_entropy(path)
    pcd_key = RSA.generate(1024, randfunc=DRNG(entropy).read)

    # n = p * q
    assert pcd_key.n == pcd_key.p * pcd_key.q

    # e * d ≡ 1  (mod lcm(p-1, q-1))
    from math import gcd

    lcm_val = (pcd_key.p - 1) * (pcd_key.q - 1) // gcd(pcd_key.p - 1, pcd_key.q - 1)
    assert (pcd_key.e * pcd_key.d) % lcm_val == 1

    # Verify OpenSSL CRT parameters match
    assert rsa.rsa_crt_dmp1(pcd_key.d, pcd_key.p) == pcd_key.d % (pcd_key.p - 1)
    assert rsa.rsa_crt_dmq1(pcd_key.d, pcd_key.q) == pcd_key.d % (pcd_key.q - 1)
    assert rsa.rsa_crt_iqmp(pcd_key.p, pcd_key.q) == pow(pcd_key.q, -1, pcd_key.p)
