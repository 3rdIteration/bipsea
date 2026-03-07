"""Tests for BIP85 GPG key derivation and OpenPGP export."""

import pytest

from bipsea.bip32types import parse_ext_key
from bipsea.bip85 import APPLICATIONS, apply_85, derive, export_gpg_armored
from bipsea.gpg import (
    KEY_TYPE_BRAINPOOL,
    KEY_TYPE_CURVE25519,
    KEY_TYPE_NIST,
    KEY_TYPE_RSA,
    KEY_TYPE_SECP256K1,
    validate_gpg_params,
)
from bipsea.util import to_hex_string

COMMON_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"


# ── determinism ──────────────────────────────────────────────────────────────


def test_gpg_deterministic():
    """Same master + path → same private key."""
    master = parse_ext_key(COMMON_XPRV)
    path = "m/83696968'/828365'/1'/256'/0'"
    r1 = apply_85(derive(master, path), path)
    r2 = apply_85(derive(master, path), path)
    assert r1["application"] == r2["application"]


def test_gpg_deterministic_brainpool():
    """Same master + path → same private key (Brainpool, uses modular reduction)."""
    master = parse_ext_key(COMMON_XPRV)
    path = "m/83696968'/828365'/4'/256'/0'"
    r1 = apply_85(derive(master, path), path)
    r2 = apply_85(derive(master, path), path)
    assert r1["application"] == r2["application"]


def test_gpg_distinct_indexes():
    """Different key_index → different keys."""
    master = parse_ext_key(COMMON_XPRV)
    r0 = apply_85(
        derive(master, "m/83696968'/828365'/1'/256'/0'"),
        "m/83696968'/828365'/1'/256'/0'",
    )
    r1 = apply_85(
        derive(master, "m/83696968'/828365'/1'/256'/1'"),
        "m/83696968'/828365'/1'/256'/1'",
    )
    assert r0["application"] != r1["application"]


# ── key type / key_bits validation ───────────────────────────────────────────


@pytest.mark.parametrize(
    "kt, kb",
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
)
def test_validate_gpg_params_ok(kt, kb):
    validate_gpg_params(kt, kb)


@pytest.mark.parametrize(
    "kt, kb",
    [
        (5, 256),
        (1, 512),
        (0, 512),
        (3, 512),
    ],
)
def test_validate_gpg_params_bad(kt, kb):
    with pytest.raises(ValueError):
        validate_gpg_params(kt, kb)


# ── ECC key derivation ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kt, kb, expected_bytes",
    [
        (1, 256, 32),
        (2, 256, 32),
        (3, 256, 32),
        (3, 384, 48),
        (3, 521, 66),
        (4, 256, 32),
        (4, 512, 64),
    ],
)
def test_ecc_key_sizes(kt, kb, expected_bytes):
    master = parse_ext_key(COMMON_XPRV)
    # Try indexes 0-9 in case scalar is out of range (Brainpool)
    for idx in range(20):
        try:
            path = f"m/83696968'/828365'/{kt}'/{kb}'/{idx}'"
            result = apply_85(derive(master, path), path)
            assert len(result["application"]) == expected_bytes * 2  # hex
            return
        except ValueError:
            continue
    pytest.fail("Could not find valid key in 20 attempts")


# ── Curve25519 subkeys ───────────────────────────────────────────────────────


def test_curve25519_subkeys():
    master = parse_ext_key(COMMON_XPRV)
    keys = {}
    for sub in [None, 0, 1, 2]:
        path = "m/83696968'/828365'/1'/256'/0'"
        if sub is not None:
            path += f"/{sub}'"
        result = apply_85(derive(master, path), path)
        keys[sub] = result["application"]
    # All keys should be distinct
    vals = list(keys.values())
    assert len(set(vals)) == len(vals)


# ── RSA key derivation ──────────────────────────────────────────────────────


@pytest.mark.slow
def test_rsa_key_derivation():
    master = parse_ext_key(COMMON_XPRV)
    path = "m/83696968'/828365'/0'/1024'/0'"
    result = apply_85(derive(master, path), path)
    assert "gpg" in result
    rsa = result["gpg"]["rsa"]
    # Verify RSA key properties
    assert rsa["e"] == 65537
    assert rsa["n"] == rsa["p"] * rsa["q"]
    assert rsa["n"].bit_length() == 1024
    assert pow(pow(42, rsa["e"], rsa["n"]), rsa["d"], rsa["n"]) == 42


# ── OpenPGP export ───────────────────────────────────────────────────────────


def test_gpg_export_curve25519():
    master = parse_ext_key(COMMON_XPRV)
    armored = export_gpg_armored(master, 1, 256, 0, uid="Test")
    assert armored.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert armored.strip().endswith("-----END PGP PRIVATE KEY BLOCK-----")


def test_gpg_export_secp256k1():
    master = parse_ext_key(COMMON_XPRV)
    armored = export_gpg_armored(master, 2, 256, 0, uid="Test")
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in armored


@pytest.mark.parametrize("kb", [256, 384])
def test_gpg_export_nist(kb):
    master = parse_ext_key(COMMON_XPRV)
    armored = export_gpg_armored(master, 3, kb, 0, uid="Test")
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in armored


def test_gpg_export_nist_521():
    master = parse_ext_key(COMMON_XPRV)
    armored = export_gpg_armored(master, 3, 521, 0, uid="Test")
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in armored


@pytest.mark.parametrize("kb", [256, 384, 512])
def test_gpg_export_brainpool(kb):
    master = parse_ext_key(COMMON_XPRV)
    armored = export_gpg_armored(master, 4, kb, 0, uid="Test")
    assert armored.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert armored.strip().endswith("-----END PGP PRIVATE KEY BLOCK-----")


@pytest.mark.slow
def test_gpg_export_rsa():
    master = parse_ext_key(COMMON_XPRV)
    armored = export_gpg_armored(master, 0, 1024, 0, uid="RSA Test")
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in armored


# ── Application code check ───────────────────────────────────────────────────


def test_gpg_app_code():
    assert APPLICATIONS["gpg"] == "828365'"
