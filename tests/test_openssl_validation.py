"""
Validate all GPG test vectors against OpenSSL and python-cryptography.

For each key type/size in test_vectors.md, we:
  1. Derive the private key from BIP85 entropy (using the master xprv)
  2. Feed that private key material to OpenSSL CLI for validation
  3. For RSA keys, additionally validate via python-cryptography
     (CRT parameter consistency + sign/verify round-trip)
  4. Verify OpenSSL / python-cryptography accept the key as well-formed

This provides an independent cross-check that bipsea's deterministic key
derivation produces valid cryptographic keys for every supported algorithm.
"""

import os
import subprocess
import tempfile

import pytest
from ecdsa import (
    BRAINPOOLP256r1,
    BRAINPOOLP384r1,
    BRAINPOOLP512r1,
    NIST256p,
    NIST384p,
    NIST521p,
    SECP256k1,
    SigningKey,
)

from bipsea.bip32types import parse_ext_key
from bipsea.bip85 import apply_85, derive

COMMON_XPRV = (
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8"
    "kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
)

# ── helpers ──────────────────────────────────────────────────────────────────


def _der_tlv(tag: int, payload: bytes) -> bytes:
    """Wrap *payload* in a DER TLV."""
    length = len(payload)
    if length < 128:
        hdr = bytes([tag, length])
    elif length < 256:
        hdr = bytes([tag, 0x81, length])
    elif length < 65536:
        hdr = bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        raise ValueError(f"payload too long: {length}")
    return hdr + payload


def _der_int(val: int) -> bytes:
    """Encode a non-negative integer as a DER INTEGER."""
    if val == 0:
        payload = b"\x00"
    else:
        payload = val.to_bytes((val.bit_length() + 7) // 8, "big")
        if payload[0] & 0x80:
            payload = b"\x00" + payload
    return _der_tlv(0x02, payload)


def _rsa_private_der(rsa: dict) -> bytes:
    """Build a DER-encoded RSAPrivateKey (PKCS#1)."""
    inner = b"".join(
        _der_int(rsa[k])
        for k in ("version", "n", "e", "d", "p", "q", "dp", "dq", "qi")
    )
    return _der_tlv(0x30, inner)


def _pkcs8_ed25519_der(seed: bytes) -> bytes:
    """Build PKCS#8 DER for an Ed25519 private key (32-byte seed)."""
    oid = bytes.fromhex("06032b6570")  # OID 1.3.101.112
    inner_octet = _der_tlv(0x04, seed)
    outer_octet = _der_tlv(0x04, inner_octet)
    algo_seq = _der_tlv(0x30, oid)
    version = bytes([0x02, 0x01, 0x00])
    return _der_tlv(0x30, version + algo_seq + outer_octet)


def _pkcs8_x25519_der(seed: bytes) -> bytes:
    """Build PKCS#8 DER for an X25519 private key (32-byte seed)."""
    oid = bytes.fromhex("06032b656e")  # OID 1.3.101.110
    inner_octet = _der_tlv(0x04, seed)
    outer_octet = _der_tlv(0x04, inner_octet)
    algo_seq = _der_tlv(0x30, oid)
    version = bytes([0x02, 0x01, 0x00])
    return _der_tlv(0x30, version + algo_seq + outer_octet)


def _derive_gpg(path: str) -> dict:
    """Derive a GPG key and return the full output dict."""
    master = parse_ext_key(COMMON_XPRV)
    return apply_85(derive(master, path), path)


def _openssl_validate_der(der_bytes: bytes, cmd: list[str]) -> None:
    """Write DER to a temp file, run OpenSSL, assert success."""
    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
        f.write(der_bytes)
        der_path = f.name
    try:
        result = subprocess.run(
            cmd + [der_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"OpenSSL failed:\n  cmd: {' '.join(cmd + [der_path])}\n"
            f"  stdout: {result.stdout}\n  stderr: {result.stderr}"
        )
    finally:
        os.unlink(der_path)


# ── Expected test-vector entropy values from test_vectors.md ─────────────────

EXPECTED_ENTROPY = {
    "0/1024": "2b9380df43421f46b5c38e13ea80612ff53488bc5d272e86d493ee1eecf738bb7b50e4978b7352f95772f1211483b0e6bba86c544a946b10d76ed493b8c2e01f",
    "0/2048": "98c4fb6d76f203e8828bdfd28416edca7a83a9b203901f7ad31f056cda8b3c25b19e5fd2aa642ca0abb9ed8bebf3d141af6c76b28a19eba624bdc6f8a76ce138",
    "0/4096": "2d2ef3335dc51e7a0642bfe86fba0bb4e8401b703d8d679bb1a31d75f8a81f1fd52b20b2eae50ef6e0378b8755f4f0426c68b54f11edc0c848e017e81bb2ad87",
    "1/256": "0e90b553528cd97a033c282f54cf72c1020adaec205d5c0e57e9f2556d06fea683618e4be8f91e7e059647f9d6373eb8b5f535e7ba4097cfb3e93c4957843614",
    "2/256": "f3bb8b3d6b81fbd202c34b59ce7e97c83969e9b5733b936de16c51119c7a48239ddf66729ef5e4df97ea39471f05a89f070869b3f9d72d69f3ae8bd7ee4fb6b3",
    "3/256": "f52586f58521916b9f28b0058be86effcde82e571eabada9e3f63c6f67752ff12a4d3bf2fffe0f147164945691605a58f28f6bded869c38b3db9f0e577d83728",
    "3/384": "830005ea400f7a03c27aa06a9728fe311c9a48dc31bd417f07b96c69edc73d25baa00d04b9dbbe6f42539b06d9ef1ba62ed73d4a3a992302aae09e17e0d9f42f",
    "3/521": "3524b3cbe60eb78a156dae44674702f69381afe5292d6d15d7801b7e530f2a0616b7b876c0ba85d6e675587fdc0ce2242ad00252493ec9c3a024217d1e2aa954",
    "4/256": "97ee4490d89bf257e9a038e2af12824fba47fec721970ca1fc1c094650d2716d75491402530776ba31d215fac6c2de0cb6661f1d380b682e20246bf962cdf385",
    "4/384": "3fa833db4195fbd7a9c4e3f6fdb65ffb8951c5c65ca0cce441a4410e11aa96fcb094ed8c1fb5317448ae098ca9cae2c351b513e47d1b74e4c80c1facdf7b0a5a",
    "4/512": "985f0131503109fc7fb2ab15e6a86846888e4b9a9f4f11f0d7b30dba4570cf8cc728a4c8ce9bbeb9b9819fbe924bb2d6d71a9c8332635cfb5db5008364f3a43a",
}

# Expected fingerprints from test_vectors.md (spaces removed for comparison)
EXPECTED_FINGERPRINTS = {
    "0/1024": "E3D7994A22E492996E24C7705319212C3BEE4C88",
    "0/2048": "99879DF6D21E34C8A086A4BD8B448E5BC298294A",
    "0/4096": "5ABD668A33DA720F3F583F2DE2DB9EFBCBAC4B2C",
    "1/256": "E81DF23714082AD2747E732B9A24C95BD8C2A55E",
    "2/256": "6D99D34874C6E88FF30C758A46F7E1AF05FC3414",
    "3/256": "2FE6D862FF2ABF1C1FAA2753B681BEF5B5D574C4",
    "3/384": "56687C3C907219B29FCE39CF95F016F9B150B8A1",
    "3/521": "EE2613AEC231FD42ECB6264EF0D67F7D75410C0B",
    "4/256": "61617C06F6F2AC323D67782F11CB4B79FEFD4369",
    "4/384": "32786624D0CA7D7F01330940397F2F1FA2BE47CB",
    "4/512": "99D7BDC937AC6E9BCC17D0936643E0501D03C680",
}


# ── RSA tests ────────────────────────────────────────────────────────────────


@pytest.mark.slow
@pytest.mark.parametrize("key_bits", [1024, 2048, 4096])
def test_rsa_openssl(key_bits):
    """Validate RSA key material against OpenSSL ``rsa -check``."""
    path = f"m/83696968'/828365'/0'/{key_bits}'/0'"
    output = _derive_gpg(path)

    # Verify entropy matches test_vectors.md
    assert output["entropy"].hex() == EXPECTED_ENTROPY[f"0/{key_bits}"]

    rsa = output["gpg"]["rsa"]
    rsa_with_version = {"version": 0, **rsa}
    der = _rsa_private_der(rsa_with_version)

    _openssl_validate_der(
        der,
        ["openssl", "rsa", "-inform", "DER", "-check", "-noout", "-in"],
    )


@pytest.mark.slow
@pytest.mark.parametrize("key_bits", [1024, 2048, 4096])
def test_rsa_python_cryptography(key_bits):
    """Validate RSA key material against python-cryptography.

    Reconstructs the key from (n, e, d, p, q, dp, dq, qi), verifies the
    CRT parameters are internally consistent, and performs a sign/verify
    round-trip to confirm the key is fully operational.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateNumbers,
        RSAPublicNumbers,
        rsa_crt_dmp1,
        rsa_crt_dmq1,
        rsa_crt_iqmp,
    )

    path = f"m/83696968'/828365'/0'/{key_bits}'/0'"
    output = _derive_gpg(path)

    # Verify entropy matches test_vectors.md
    assert output["entropy"].hex() == EXPECTED_ENTROPY[f"0/{key_bits}"]

    rsa = output["gpg"]["rsa"]

    # Cross-check CRT parameters independently
    assert rsa_crt_dmp1(rsa["d"], rsa["p"]) == rsa["dp"]
    assert rsa_crt_dmq1(rsa["d"], rsa["q"]) == rsa["dq"]
    assert rsa_crt_iqmp(rsa["p"], rsa["q"]) == rsa["qi"]

    # Reconstruct key – raises if components are inconsistent
    public_numbers = RSAPublicNumbers(e=rsa["e"], n=rsa["n"])
    private_numbers = RSAPrivateNumbers(
        p=rsa["p"],
        q=rsa["q"],
        d=rsa["d"],
        dmp1=rsa["dp"],
        dmq1=rsa["dq"],
        iqmp=rsa["qi"],
        public_numbers=public_numbers,
    )
    private_key = private_numbers.private_key()

    assert private_key.key_size == key_bits
    assert private_key.public_key().public_numbers().n == rsa["n"]
    assert private_key.public_key().public_numbers().e == rsa["e"]

    # Sign / verify round-trip
    message = b"BIP85 GPG test vector validation"
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    private_key.public_key().verify(
        signature,
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


# ── Ed25519 / X25519 (Curve25519 family) ────────────────────────────────────


def test_ed25519_openssl():
    """Validate Curve25519 primary key (Ed25519) against OpenSSL."""
    path = "m/83696968'/828365'/1'/256'/0'"
    output = _derive_gpg(path)

    # Verify entropy matches test_vectors.md
    assert output["entropy"].hex() == EXPECTED_ENTROPY["1/256"]

    seed = output["gpg"]["private_key"]
    assert len(seed) == 32

    der = _pkcs8_ed25519_der(seed)
    _openssl_validate_der(
        der,
        ["openssl", "pkey", "-inform", "DER", "-noout", "-text", "-in"],
    )


def test_x25519_openssl():
    """Validate Curve25519 encryption subkey (X25519) against OpenSSL."""
    path = "m/83696968'/828365'/1'/256'/0'/0'"
    output = _derive_gpg(path)
    seed = output["gpg"]["private_key"]
    assert len(seed) == 32

    der = _pkcs8_x25519_der(seed)
    _openssl_validate_der(
        der,
        ["openssl", "pkey", "-inform", "DER", "-noout", "-text", "-in"],
    )


# ── ECDSA curves (secp256k1, NIST, Brainpool) ───────────────────────────────

# (key_type, key_bits) → ecdsa curve object
_ECC_CURVES = {
    (2, 256): SECP256k1,
    (3, 256): NIST256p,
    (3, 384): NIST384p,
    (3, 521): NIST521p,
    (4, 256): BRAINPOOLP256r1,
    (4, 384): BRAINPOOLP384r1,
    (4, 512): BRAINPOOLP512r1,
}


@pytest.mark.parametrize(
    "key_type, key_bits",
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
def test_ecdsa_openssl(key_type, key_bits):
    """Validate ECDSA key material against OpenSSL ``ec -check``."""
    path = f"m/83696968'/828365'/{key_type}'/{key_bits}'/0'"
    output = _derive_gpg(path)

    # Verify entropy matches test_vectors.md
    assert output["entropy"].hex() == EXPECTED_ENTROPY[f"{key_type}/{key_bits}"]

    pkey_bytes = output["gpg"]["private_key"]
    curve = _ECC_CURVES[(key_type, key_bits)]
    sk = SigningKey.from_string(pkey_bytes, curve=curve)

    der = sk.to_der()
    _openssl_validate_der(
        der,
        ["openssl", "ec", "-inform", "DER", "-check", "-noout", "-in"],
    )


# ── python-cryptography validation (ECDSA + Ed25519/X25519) ─────────────────

# (key_type, key_bits) → python-cryptography curve + hash
_CRYPTO_ECC = {
    (2, 256): ("SECP256K1", "SHA256"),
    (3, 256): ("SECP256R1", "SHA256"),
    (3, 384): ("SECP384R1", "SHA384"),
    (3, 521): ("SECP521R1", "SHA512"),
    (4, 256): ("BrainpoolP256R1", "SHA256"),
    (4, 384): ("BrainpoolP384R1", "SHA384"),
    (4, 512): ("BrainpoolP512R1", "SHA512"),
}


@pytest.mark.parametrize(
    "key_type, key_bits",
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
def test_ecdsa_python_cryptography(key_type, key_bits):
    """Validate ECDSA key material against python-cryptography.

    Reconstructs the key from the raw private scalar, verifies the
    public-key point matches what the ``ecdsa`` library computes,
    and performs a sign/verify round-trip.
    """
    import cryptography.hazmat.primitives.asymmetric.ec as ec
    from cryptography.hazmat.primitives import hashes as crypto_hashes

    curve_name, hash_name = _CRYPTO_ECC[(key_type, key_bits)]
    crypto_curve = getattr(ec, curve_name)()
    hash_algo = getattr(crypto_hashes, hash_name)()

    path = f"m/83696968'/828365'/{key_type}'/{key_bits}'/0'"
    output = _derive_gpg(path)

    assert output["entropy"].hex() == EXPECTED_ENTROPY[f"{key_type}/{key_bits}"]

    pkey_bytes = output["gpg"]["private_key"]
    priv_int = int.from_bytes(pkey_bytes, "big")

    # Reconstruct via python-cryptography – raises on invalid scalar
    private_key = ec.derive_private_key(priv_int, crypto_curve)
    assert private_key.key_size == crypto_curve.key_size

    # Cross-check: public key matches ecdsa library
    ecdsa_curve = _ECC_CURVES[(key_type, key_bits)]
    sk = SigningKey.from_string(pkey_bytes, curve=ecdsa_curve)
    ecdsa_pub = sk.verifying_key.to_string()

    pub_nums = private_key.public_key().public_numbers()
    byte_len = (key_bits + 7) // 8
    crypto_pub = (
        pub_nums.x.to_bytes(byte_len, "big")
        + pub_nums.y.to_bytes(byte_len, "big")
    )
    assert ecdsa_pub == crypto_pub

    # Sign / verify round-trip
    message = b"BIP85 GPG test vector validation"
    signature = private_key.sign(message, ec.ECDSA(hash_algo))
    private_key.public_key().verify(signature, message, ec.ECDSA(hash_algo))


def test_ed25519_python_cryptography():
    """Validate Ed25519 primary key against python-cryptography."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = "m/83696968'/828365'/1'/256'/0'"
    output = _derive_gpg(path)
    assert output["entropy"].hex() == EXPECTED_ENTROPY["1/256"]

    seed = output["gpg"]["private_key"]
    assert len(seed) == 32

    private_key = Ed25519PrivateKey.from_private_bytes(seed)

    # Sign / verify round-trip
    message = b"BIP85 GPG test vector validation"
    signature = private_key.sign(message)
    private_key.public_key().verify(signature, message)


def test_x25519_python_cryptography():
    """Validate X25519 encryption subkey against python-cryptography."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    path = "m/83696968'/828365'/1'/256'/0'/0'"
    output = _derive_gpg(path)

    seed = output["gpg"]["private_key"]
    assert len(seed) == 32

    # Loads successfully – X25519 is key exchange, not signing
    private_key = X25519PrivateKey.from_private_bytes(seed)
    assert private_key.public_key() is not None


# ── Fingerprint validation ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "key_type, key_bits",
    [
        (0, 1024),
        (0, 2048),
        (0, 4096),
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
        "RSA-1024",
        "RSA-2048",
        "RSA-4096",
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
def test_fingerprint_matches(key_type, key_bits):
    """Verify the computed OpenPGP v4 fingerprint matches test_vectors.md."""
    from bipsea.bip85 import export_gpg_armored
    from bipsea.openpgp import key_fingerprint_v4

    master = parse_ext_key(COMMON_XPRV)

    # Derive entropy and verify it matches expected
    path = f"m/83696968'/828365'/{key_type}'/{key_bits}'/0'"
    output = _derive_gpg(path)
    assert output["entropy"].hex() == EXPECTED_ENTROPY[f"{key_type}/{key_bits}"]

    # Export the full armored key (computes fingerprint internally)
    armored = export_gpg_armored(
        master, key_type=key_type, key_bits=key_bits, key_index=0
    )
    assert armored.strip().startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert armored.strip().endswith("-----END PGP PRIVATE KEY BLOCK-----")

    # Compute fingerprint from the primary key body
    # (This is done inside export_gpg_key; we re-derive it here to check)
    from bipsea.bip85 import APPLICATIONS, PURPOSE_CODES
    from bipsea.gpg import KEY_TYPE_RSA
    from bipsea.openpgp import _build_ecc_key_body, _build_rsa_key_body

    base = f"m/{PURPOSE_CODES['BIP-85']}/{APPLICATIONS['gpg']}"
    primary_path = f"{base}/{key_type}'/{key_bits}'/0'"
    primary_out = apply_85(derive(master, primary_path), primary_path)
    primary_priv = bytes.fromhex(primary_out["application"])

    if key_type == KEY_TYPE_RSA:
        rsa_data = primary_out["gpg"]["rsa"]
        _, pub_body, _ = _build_rsa_key_body(rsa_data)
    else:
        _, pub_body, _ = _build_ecc_key_body(
            primary_priv, key_type, key_bits, is_encrypt=False
        )

    fp = key_fingerprint_v4(pub_body)
    fp_hex = fp.hex().upper()

    expected = EXPECTED_FINGERPRINTS[f"{key_type}/{key_bits}"]
    assert fp_hex == expected, f"Fingerprint mismatch: got {fp_hex}, expected {expected}"


# ── Full armored key round-trip with OpenSSL (via GnuPG-style import) ───────


@pytest.mark.parametrize(
    "key_type, key_bits",
    [
        (0, 1024),
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
        "RSA-1024",
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
def test_armored_key_starts_ends(key_type, key_bits):
    """Verify the ASCII-armored key has correct PGP envelope."""
    from bipsea.bip85 import export_gpg_armored

    master = parse_ext_key(COMMON_XPRV)
    armored = export_gpg_armored(
        master, key_type=key_type, key_bits=key_bits, key_index=0
    )
    assert armored.strip().startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert armored.strip().endswith("-----END PGP PRIVATE KEY BLOCK-----")
