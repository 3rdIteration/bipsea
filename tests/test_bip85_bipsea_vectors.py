"""Cross-implementation GPG fingerprint and key validation tests.

Verifies that bipsea's GPG key derivation produces the expected v4
fingerprints for all supported key types, and cross-validates the
derived key material against the ``cryptography`` library.
"""

import pytest

from bipsea.bip32types import parse_ext_key
from bipsea.bip85 import apply_85, derive, export_gpg_armored
from bipsea.gpg import KEY_TYPE_RSA, ECC_CURVES
from bipsea.openpgp import (
    _build_ecc_key_body,
    _build_rsa_key_body,
    key_fingerprint_v4,
)

COMMON_XPRV = (
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmba"
    "LLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
)

# Expected v4 fingerprints (hex) for each (key_type, key_bits) at index 0.
# RSA vectors generated with PyCryptodome RSA.generate (FIPS 186-4).
EXPECTED_FINGERPRINTS = {
    (0, 1024): "874a39644ed0255deec18e0e1e6388649672cf70",
    (0, 2048): "99879df6d21e34c8a086a4bd8b448e5bc298294a",
    (0, 4096): "24c25a48383e117546871767d9a05ca64f2f6a85",
    (1, 256): "e81df23714082ad2747e732b9a24c95bd8c2a55e",
    (2, 256): "6d99d34874c6e88ff30c758a46f7e1af05fc3414",
    (3, 256): "2fe6d862ff2abf1c1faa2753b681bef5b5d574c4",
    (3, 384): "56687c3c907219b29fce39cf95f016f9b150b8a1",
    (3, 521): "ee2613aec231fd42ecb6264ef0d67f7d75410c0b",
    (4, 256): "61617c06f6f2ac323d67782f11cb4b79fefd4369",
    (4, 384): "32786624d0ca7d7f01330940397f2f1fa2be47cb",
    (4, 512): "99d7bdc937ac6e9bcc17d0936643e0501d03c680",
}


def _compute_fingerprint(kt, kb, result):
    """Compute the v4 fingerprint for a GPG primary key."""
    priv = bytes.fromhex(result["application"])
    if kt == KEY_TYPE_RSA:
        rsa = result["gpg"]["rsa"]
        _, pub_body, _ = _build_rsa_key_body(rsa)
    else:
        _, pub_body, _ = _build_ecc_key_body(priv, kt, kb, is_encrypt=False)
    return key_fingerprint_v4(pub_body).hex()


# ── fingerprint tests ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kt, kb",
    [(0, 1024), (0, 2048), (0, 4096)],
    ids=["RSA-1024", "RSA-2048", "RSA-4096"],
)
@pytest.mark.slow
def test_rsa_fingerprint(kt, kb):
    master = parse_ext_key(COMMON_XPRV)
    path = f"m/83696968'/828365'/{kt}'/{kb}'/0'"
    result = apply_85(derive(master, path), path)
    fp = _compute_fingerprint(kt, kb, result)
    assert fp == EXPECTED_FINGERPRINTS[(kt, kb)]


@pytest.mark.parametrize(
    "kt, kb",
    [
        (1, 256),
        (2, 256),
        (3, 256),
        (3, 384),
        (3, 521),
        (4, 256),
        (4, 384),
        (4, 512),
    ],
    ids=[
        "Curve25519",
        "secp256k1",
        "NIST-P256",
        "NIST-P384",
        "NIST-P521",
        "Brainpool-P256",
        "Brainpool-P384",
        "Brainpool-P512",
    ],
)
def test_ecc_fingerprint(kt, kb):
    master = parse_ext_key(COMMON_XPRV)
    path = f"m/83696968'/828365'/{kt}'/{kb}'/0'"
    result = apply_85(derive(master, path), path)
    fp = _compute_fingerprint(kt, kb, result)
    assert fp == EXPECTED_FINGERPRINTS[(kt, kb)]


# ── cross-validation against python-cryptography ─────────────────────────────


@pytest.mark.parametrize(
    "kt, kb",
    [(0, 1024), (0, 2048)],
    ids=["RSA-1024", "RSA-2048"],
)
@pytest.mark.slow
def test_rsa_cryptography_validation(kt, kb):
    """Validate RSA key components via python-cryptography roundtrip."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    master = parse_ext_key(COMMON_XPRV)
    path = f"m/83696968'/828365'/{kt}'/{kb}'/0'"
    result = apply_85(derive(master, path), path)
    comp = result["gpg"]["rsa"]

    pub_nums = rsa.RSAPublicNumbers(comp["e"], comp["n"])
    priv_nums = rsa.RSAPrivateNumbers(
        p=comp["p"],
        q=comp["q"],
        d=comp["d"],
        dmp1=comp["dp"],
        dmq1=comp["dq"],
        iqmp=comp["qi"],
        public_numbers=pub_nums,
    )
    key = priv_nums.private_key(default_backend())
    msg = b"bipsea cross-validation"
    ct = key.public_key().encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    pt = key.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    assert pt == msg


def test_ed25519_cryptography_validation():
    """Validate Ed25519 key via python-cryptography sign/verify."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    master = parse_ext_key(COMMON_XPRV)
    path = "m/83696968'/828365'/1'/256'/0'"
    result = apply_85(derive(master, path), path)
    priv = bytes.fromhex(result["application"])

    ed_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv)
    sig = ed_key.sign(b"bipsea cross-validation")
    ed_key.public_key().verify(sig, b"bipsea cross-validation")


@pytest.mark.parametrize(
    "kt, kb",
    [
        (2, 256),
        (3, 256),
        (3, 384),
        (3, 521),
        (4, 256),
        (4, 384),
        (4, 512),
    ],
    ids=[
        "secp256k1",
        "NIST-P256",
        "NIST-P384",
        "NIST-P521",
        "Brainpool-P256",
        "Brainpool-P384",
        "Brainpool-P512",
    ],
)
def test_ecdsa_cryptography_validation(kt, kb):
    """Validate ECDSA key by comparing public key coordinates with
    python-cryptography derivation."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    from ecdsa import SigningKey

    curve_map = {
        (2, 256): ec.SECP256K1(),
        (3, 256): ec.SECP256R1(),
        (3, 384): ec.SECP384R1(),
        (3, 521): ec.SECP521R1(),
        (4, 256): ec.BrainpoolP256R1(),
        (4, 384): ec.BrainpoolP384R1(),
        (4, 512): ec.BrainpoolP512R1(),
    }
    master = parse_ext_key(COMMON_XPRV)
    path = f"m/83696968'/828365'/{kt}'/{kb}'/0'"
    result = apply_85(derive(master, path), path)
    priv = bytes.fromhex(result["application"])
    scalar = int.from_bytes(priv, "big")

    # python-cryptography derivation
    crypto_key = ec.derive_private_key(scalar, curve_map[(kt, kb)], default_backend())
    crypto_pub = crypto_key.public_key().public_numbers()

    # ecdsa library derivation
    ecdsa_curve = ECC_CURVES[(kt, kb)]
    sk = SigningKey.from_string(priv, curve=ecdsa_curve)
    vk = sk.get_verifying_key()
    ecdsa_point = vk.pubkey.point

    assert ecdsa_point.x() == crypto_pub.x
    assert ecdsa_point.y() == crypto_pub.y


# ── ASCII-armored export ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kt, kb",
    [
        (1, 256),
        (2, 256),
        (3, 256),
        (3, 384),
        (3, 521),
        (4, 256),
        (4, 384),
        (4, 512),
    ],
    ids=[
        "Curve25519",
        "secp256k1",
        "NIST-P256",
        "NIST-P384",
        "NIST-P521",
        "Brainpool-P256",
        "Brainpool-P384",
        "Brainpool-P512",
    ],
)
def test_ecc_armored_export(kt, kb):
    master = parse_ext_key(COMMON_XPRV)
    armored = export_gpg_armored(master, kt, kb, 0, uid="BIP85")
    assert armored.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert armored.strip().endswith("-----END PGP PRIVATE KEY BLOCK-----")


@pytest.mark.slow
def test_rsa_armored_export():
    master = parse_ext_key(COMMON_XPRV)
    armored = export_gpg_armored(master, 0, 1024, 0, uid="BIP85")
    assert armored.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert armored.strip().endswith("-----END PGP PRIVATE KEY BLOCK-----")
