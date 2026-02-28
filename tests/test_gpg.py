"""Tests for BIP85 GPG key generation."""

import os
import subprocess
import tempfile

import pytest

from bipsea.bip32types import parse_ext_key
from bipsea.bip85 import APPLICATIONS, DRNG, PURPOSE_CODES, derive, to_entropy
from bipsea.gpg import (
    GPG_KEY_TYPES,
    GPG_VALID_KEY_BITS,
    GENESIS_TIMESTAMP,
    _generate_ecdh_material,
    _generate_ecdsa_material,
    _generate_ed25519_material,
    _generate_rsa_material,
    _generate_x25519_material,
    _needs_drng,
    build_gpg_key,
    generate_gpg_key_material,
    generate_rsa_key,
    validate_gpg_params,
    x25519_public_key,
)

COMMON_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"


def _make_gpg_key(key_type, key_bits, key_index=0, uid="BIP85 Test"):
    """Helper to generate a GPG key from the common test XPRV."""
    master = parse_ext_key(COMMON_XPRV)
    from bipsea.bipsea import _derive_gpg

    return _derive_gpg(master, key_type, key_bits, key_index, uid)


def _gpg_import_test(armored_key):
    """Import key into a temp GnuPG instance and return parsed output."""
    gnupghome = tempfile.mkdtemp()
    try:
        env = os.environ.copy()
        env["GNUPGHOME"] = gnupghome
        # Import key
        result = subprocess.run(
            ["gpg2", "--batch", "--import"],
            input=armored_key,
            capture_output=True,
            text=True,
            env=env,
        )
        # List keys
        list_result = subprocess.run(
            ["gpg2", "--list-secret-keys", "--keyid-format", "long"],
            capture_output=True,
            text=True,
            env=env,
        )
        return result, list_result
    finally:
        subprocess.run(["rm", "-rf", gnupghome], capture_output=True)


class TestX25519:
    def test_public_key_length(self):
        import hashlib

        seed = hashlib.sha256(b"test").digest()
        pub = x25519_public_key(seed)
        assert len(pub) == 32

    def test_deterministic(self):
        seed = bytes(range(32))
        assert x25519_public_key(seed) == x25519_public_key(seed)

    def test_different_seeds(self):
        seed1 = bytes([8] + [0] * 31)
        seed2 = bytes([16] + [0] * 31)
        assert x25519_public_key(seed1) != x25519_public_key(seed2)


class TestValidation:
    def test_valid_params(self):
        for kt in GPG_KEY_TYPES:
            for kb in GPG_VALID_KEY_BITS[kt]:
                validate_gpg_params(kt, kb)

    @pytest.mark.parametrize(
        "key_type, key_bits",
        [(0, 512), (1, 384), (2, 384), (3, 128), (4, 1024), (5, 256)],
    )
    def test_invalid_params(self, key_type, key_bits):
        with pytest.raises(ValueError):
            validate_gpg_params(key_type, key_bits)


class TestKeyMaterial:
    def test_ed25519_material(self):
        import hashlib

        entropy = hashlib.sha512(b"ed25519 test").digest()
        mat = _generate_ed25519_material(entropy)
        assert mat.algo == 22  # EdDSA
        assert mat.sign_func is not None
        assert len(mat.public_body) > 32
        assert len(mat.secret_body) > 0

    def test_x25519_material(self):
        import hashlib

        entropy = hashlib.sha512(b"x25519 test").digest()
        mat = _generate_x25519_material(entropy)
        assert mat.algo == 18  # ECDH
        assert mat.sign_func is None
        assert len(mat.public_body) > 32

    def test_ecdsa_secp256k1_material(self):
        import hashlib

        entropy = hashlib.sha512(b"secp256k1 test").digest()
        mat = _generate_ecdsa_material(entropy, 2, 256)
        assert mat.algo == 19  # ECDSA
        assert mat.sign_func is not None

    def test_ecdh_secp256k1_material(self):
        import hashlib

        entropy = hashlib.sha512(b"secp256k1 ecdh test").digest()
        mat = _generate_ecdh_material(entropy, 2, 256)
        assert mat.algo == 18  # ECDH
        assert mat.sign_func is None


class TestDRNGNeeded:
    @pytest.mark.parametrize(
        "key_type, key_bits, expected",
        [
            (0, 1024, True),
            (0, 2048, True),
            (0, 4096, True),
            (1, 256, False),
            (2, 256, False),
            (3, 256, False),
            (3, 384, False),
            (3, 521, True),
            (4, 256, False),
            (4, 384, False),
            (4, 512, False),
        ],
    )
    def test_needs_drng(self, key_type, key_bits, expected):
        assert _needs_drng(key_type, key_bits) == expected


class TestDerivationPaths:
    def test_primary_key_path(self):
        """Verify the derivation path format matches the spec."""
        master = parse_ext_key(COMMON_XPRV)
        key_type, key_bits, key_index = 1, 256, 0
        path = f"m/{PURPOSE_CODES['BIP-85']}/{APPLICATIONS['gpg']}/{key_type}'/{key_bits}'/{key_index}'"
        assert path == "m/83696968'/828365'/1'/256'/0'"
        # Should not raise
        derived = derive(master, path)
        assert derived is not None

    def test_subkey_paths(self):
        """Verify subkey derivation paths."""
        master = parse_ext_key(COMMON_XPRV)
        base = "m/83696968'/828365'/1'/256'/0'"
        for sub_idx in (0, 1, 2):
            path = f"{base}/{sub_idx}'"
            derived = derive(master, path)
            assert derived is not None

    def test_different_indexes_different_keys(self):
        """Different key_index values produce different keys."""
        key0 = _make_gpg_key(1, 256, key_index=0)
        key1 = _make_gpg_key(1, 256, key_index=1)
        assert key0 != key1

    def test_deterministic(self):
        """Same parameters produce same key."""
        key1 = _make_gpg_key(1, 256, key_index=0, uid="Test")
        key2 = _make_gpg_key(1, 256, key_index=0, uid="Test")
        assert key1 == key2


class TestASCIIArmor:
    def test_armor_format(self):
        output = _make_gpg_key(1, 256)
        assert output.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----\n")
        assert output.rstrip().endswith("-----END PGP PRIVATE KEY BLOCK-----")

    def test_genesis_timestamp(self):
        """Keys use the Bitcoin genesis block timestamp."""
        assert GENESIS_TIMESTAMP == 1231006505


class TestGPGImport:
    """Test that generated keys can be imported into GnuPG2."""

    @pytest.mark.parametrize(
        "key_type, key_bits, expected_algo",
        [
            (1, 256, "ed25519"),
            (2, 256, "secp256k1"),
            (3, 256, "nistp256"),
            (3, 384, "nistp384"),
            (4, 256, "brainpoolP256r1"),
        ],
    )
    def test_ecc_import(self, key_type, key_bits, expected_algo):
        armored = _make_gpg_key(key_type, key_bits)
        import_result, list_result = _gpg_import_test(armored)
        assert "imported" in import_result.stderr
        assert "secret key imported" in import_result.stderr
        assert expected_algo in list_result.stdout
        # Verify subkeys: [E], [A], [S]
        assert "[E]" in list_result.stdout
        assert "[A]" in list_result.stdout
        assert "[S]" in list_result.stdout
        assert "[C]" in list_result.stdout

    @pytest.mark.slow
    @pytest.mark.parametrize(
        "key_type, key_bits, expected_algo",
        [
            (3, 521, "nistp521"),
            (4, 384, "brainpoolP384r1"),
            (4, 512, "brainpoolP512r1"),
        ],
    )
    def test_large_ecc_import(self, key_type, key_bits, expected_algo):
        armored = _make_gpg_key(key_type, key_bits)
        import_result, list_result = _gpg_import_test(armored)
        assert "imported" in import_result.stderr
        assert expected_algo in list_result.stdout

    @pytest.mark.slow
    def test_rsa_1024_import(self):
        armored = _make_gpg_key(0, 1024)
        import_result, list_result = _gpg_import_test(armored)
        assert "imported" in import_result.stderr
        assert "rsa1024" in list_result.stdout

    def test_uid_in_output(self):
        uid = "Custom UID <custom@example.com>"
        armored = _make_gpg_key(1, 256, uid=uid)
        import_result, list_result = _gpg_import_test(armored)
        assert uid in list_result.stdout

    def test_creation_date(self):
        """Verify keys use the genesis timestamp (2009-01-03)."""
        armored = _make_gpg_key(1, 256)
        import_result, list_result = _gpg_import_test(armored)
        assert "2009-01-03" in list_result.stdout


class TestRSA:
    @pytest.mark.slow
    def test_rsa_keygen_deterministic(self):
        """RSA key generation with the same DRNG produces identical keys."""
        import hashlib

        entropy = hashlib.sha512(b"rsa test seed").digest()
        drng1 = DRNG(entropy)
        drng2 = DRNG(entropy)
        key1 = generate_rsa_key(1024, drng1.read)
        key2 = generate_rsa_key(1024, drng2.read)
        assert key1 == key2

    @pytest.mark.slow
    def test_rsa_key_valid(self):
        """Verify RSA key components are mathematically correct."""
        import hashlib

        entropy = hashlib.sha512(b"rsa validation seed").digest()
        drng = DRNG(entropy)
        n, e, d, p, q, u = generate_rsa_key(1024, drng.read)
        # n = p * q
        assert n == p * q
        # e * d ≡ 1 (mod lcm(p-1, q-1))
        from math import gcd

        lcm_val = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        assert (e * d) % lcm_val == 1
        # u = p^-1 mod q
        assert (u * p) % q == 1
        # encrypt/decrypt
        msg = 42
        cipher = pow(msg, e, n)
        assert pow(cipher, d, n) == msg
