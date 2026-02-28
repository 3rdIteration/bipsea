import base64
import hashlib
import logging
import math
import re
import textwrap
from typing import Dict, Union

import base58

from .bip32 import VERSIONS, ExtendedKey
from .bip32 import derive_key as derive_key_bip32
from .bip32 import hmac_sha512
from .bip39 import LANGUAGES, N_WORDS_META, entropy_to_words, validate_mnemonic_words
from .util import LOGGER_NAME, to_hex_string

logger = logging.getLogger(LOGGER_NAME)


APPLICATIONS = {
    "base64": "707764'",
    "base85": "707785'",
    "dice": "89101'",
    "drng": "0'",
    "gpg": "828365'",
    "hex": "128169'",
    "mnemonic": "39'",
    "wif": "2'",
    "xprv": "32'",
}

RANGES = {
    "base64": (20, 86),
    "base85": (10, 80),
    "hex": (16, 64),
    "dice": (1, 10_000),
}

PURPOSE_CODES = {"BIP-85": "83696968'"}

HMAC_KEY = b"bip-entropy-from-k"
OPENPGP_GENESIS_TIMESTAMP = 1231006505

GPG_KEY_TYPE_TO_BITS = {
    0: {1024, 2048, 4096},
    1: {256},
    2: {256},
    3: {256, 384, 521},
    4: {256, 384, 512},
}

INDEX_TO_LANGUAGE = {
    "0'": "english",
    "1'": "japanese",
    "2'": "korean",
    "3'": "spanish",
    "4'": "chinese_simplified",
    "5'": "chinese_traditional",
    "6'": "french",
    "7'": "italian",
    "8'": "czech",
    "9'": "portuguese",  # not in BIP-85 but in BIP-39 test vectors
}

assert set(INDEX_TO_LANGUAGE.values()) == set(LANGUAGES.keys())


def apply_85(derived_key: ExtendedKey, path: str) -> Dict[str, Union[bytes, str]]:
    """returns a dict with 'entropy': bytes and 'application': str"""
    segments = split_and_validate(path)
    purpose = segments[1]
    if purpose != PURPOSE_CODES["BIP-85"]:
        raise ValueError(f"Not a BIP85 path: {path}")
    if len(segments) < 4 or not all(s.endswith("'") for s in segments[1:]):
        raise ValueError(
            f"Paths should have 4+ segments, all hardened children: {path}"
        )
    app, *indexes = segments[2:]

    entropy = to_entropy(derived_key.data[1:])

    if app == APPLICATIONS["mnemonic"]:
        language_index, n_words = indexes[:2]
        n_words = int(n_words.rstrip("'"))
        if n_words not in N_WORDS_META.keys():
            raise ValueError(f"Unsupported number of words: {n_words}.")
        language = INDEX_TO_LANGUAGE[language_index]
        n_bytes = N_WORDS_META[n_words]["entropy_bits"] // 8
        trimmed_entropy = entropy[:n_bytes]
        words = entropy_to_words(n_words, trimmed_entropy, language)
        assert validate_mnemonic_words(words, language)

        return {
            "entropy": trimmed_entropy,
            "application": " ".join(words),
        }
    elif app == APPLICATIONS["wif"]:
        trimmed_entropy = entropy[: 256 // 8]
        prefix = b"\x80" if derived_key.get_network() == "mainnet" else b"\xef"
        suffix = b"\x01"  # use with compressed public keys because BIP-32
        extended = prefix + trimmed_entropy + suffix

        return {
            "entropy": trimmed_entropy,
            "application": base58.b58encode_check(extended).decode("utf-8"),
        }
    elif app == APPLICATIONS["xprv"]:
        derived_key = ExtendedKey(
            version=VERSIONS["mainnet"]["private"],
            depth=bytes(1),
            finger=bytes(4),
            child_number=bytes(4),
            chain_code=entropy[:32],
            data=bytes(1) + entropy[32:],
        )

        return {
            "entropy": entropy[32:],
            "application": str(derived_key),
        }
    elif app == APPLICATIONS["hex"]:
        num_bytes = int(indexes[0].rstrip("'"))
        if not (16 <= num_bytes <= 64):
            raise ValueError(f"Expected num_bytes in [16, 64], got {num_bytes}")

        return {"entropy": entropy, "application": to_hex_string(entropy[:num_bytes])}
    elif app == APPLICATIONS["base64"]:
        pwd_len = int(indexes[0].rstrip("'"))
        if not (20 <= pwd_len <= 86):
            raise ValueError(f"Expected pwd_len in [20, 86], got {pwd_len}")

        return {
            "entropy": entropy,
            "application": base64.b64encode(entropy).decode("utf-8")[:pwd_len],
        }
    elif app == APPLICATIONS["base85"]:
        pwd_len = int(indexes[0].rstrip("'"))
        if not (10 <= pwd_len <= 80):
            raise ValueError("Expected pwd_len in [10, 80], got {pwd_len}")

        return {
            "entropy": entropy,
            "application": base64.b85encode(entropy).decode("utf-8")[:pwd_len],
        }
    elif app == APPLICATIONS["dice"]:
        sides, rolls, index = (int(s.rstrip("'")) for s in indexes[:3])
        return {
            "entropy": entropy,
            "application": do_rolls(entropy, sides, rolls, index),
        }
    elif app == APPLICATIONS["gpg"]:
        if len(indexes) < 3:
            raise ValueError(
                f"Expected key_type', key_bits', and index' after 828365': {path}"
            )
        key_type, key_bits, index = (int(s.rstrip("'")) for s in indexes[:3])
        if index < 0:
            raise ValueError(f"Unsupported GPG key index: {index}")
        if key_type not in GPG_KEY_TYPE_TO_BITS:
            raise ValueError(f"Unsupported GPG key_type: {key_type}")
        if key_bits not in GPG_KEY_TYPE_TO_BITS[key_type]:
            raise ValueError(
                f"Unsupported GPG key_bits {key_bits} for key_type {key_type}"
            )
        return {"entropy": entropy, "application": to_hex_string(entropy)}
    else:
        raise NotImplementedError(f"Unsupported BIP-85 application {app}")


def to_entropy(data: bytes) -> bytes:
    return hmac_sha512(key=HMAC_KEY, data=data)


def to_gpg_private_key_block(entropy: bytes, key_type: int, key_bits: int) -> str:
    if key_type != 0:
        raise NotImplementedError(
            f"GnuPG2 importable private key blocks are currently supported only for RSA key_type=0, got {key_type}"
        )
    try:
        from Crypto.PublicKey import RSA
    except ImportError as err:
        raise ImportError(
            "pycryptodome is required for RSA OpenPGP private key block output"
        ) from err

    key = RSA.generate(key_bits, randfunc=DRNG(entropy).read)
    public_fields = (
        b"\x04"
        + OPENPGP_GENESIS_TIMESTAMP.to_bytes(4, "big")
        + b"\x01"
        + _to_mpi(key.n)
        + _to_mpi(key.e)
    )
    secret_fields = (
        _to_mpi(key.d)
        + _to_mpi(key.p)
        + _to_mpi(key.q)
        + _to_mpi(pow(key.p, -1, key.q))
    )
    checksum = (sum(secret_fields) % 65536).to_bytes(2, "big")
    secret_packet_body = public_fields + b"\x00" + secret_fields + checksum
    secret_packet = _new_packet_header(5, len(secret_packet_body)) + secret_packet_body
    return _to_armor(secret_packet, "PGP PRIVATE KEY BLOCK")


def _to_mpi(value: int) -> bytes:
    byte_len = max(1, (value.bit_length() + 7) // 8)
    value_bytes = value.to_bytes(byte_len, "big")
    return value.bit_length().to_bytes(2, "big") + value_bytes


def _new_packet_header(tag: int, length: int) -> bytes:
    header = bytes([0xC0 | tag])
    if length < 192:
        return header + bytes([length])
    if length <= 8383:
        length -= 192
        return header + bytes([(length >> 8) + 192, length & 0xFF])
    return header + bytes([255]) + length.to_bytes(4, "big")


def _to_armor(data: bytes, title: str) -> str:
    payload = base64.b64encode(data).decode("ascii")
    lines = textwrap.wrap(payload, 64)
    checksum = base64.b64encode(_crc24(data)).decode("ascii")
    return (
        f"-----BEGIN {title}-----\n\n"
        + "\n".join(lines)
        + f"\n={checksum}\n-----END {title}-----"
    )


def _crc24(data: bytes) -> bytes:
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return (crc & 0xFFFFFF).to_bytes(3, "big")


def derive(master: ExtendedKey, path: str, private: bool = True) -> ExtendedKey:
    if not master.is_private():
        raise ValueError("Derivations should begin with a private master key")

    return derive_key_bip32(master, split_and_validate(path), private)


class DRNG:
    def __init__(self, seed: bytes):
        if len(seed) != 64:
            raise ValueError("Seed must be exactly 64 bytes long")
        self.shake = hashlib.shake_256(seed)
        self.cursor = 0

    def read(self, n: int) -> bytes:
        start = self.cursor
        self.cursor = stop = start + n

        return self.shake.digest(stop)[start:stop]


def split_and_validate(path: str):
    segments = path.split("/")
    if segments[0] != "m":
        raise ValueError(f"Expected 'm' (xprv) at root of derivation path: {path}")
    pattern = r"^\d+['hH]?$"
    if not all(re.match(pattern, s) for s in segments[1:]):
        raise ValueError(f"Unexpected path segments: {path}")

    return segments


def do_rolls(entropy: bytes, sides: int, rolls: int, index: int) -> str:
    """sides > 1, 1 < rolls > 100"""
    max_width = len(str(sides - 1))
    history = []
    bits_per_roll = math.ceil(math.log(sides, 2))
    bytes_per_roll = math.ceil(bits_per_roll / 8)
    drng = DRNG(entropy)
    while len(history) < rolls:
        trial_int = int.from_bytes(drng.read(bytes_per_roll), "big")
        available_bits = 8 * bytes_per_roll
        excess_bits = available_bits - bits_per_roll
        trial_int >>= excess_bits
        if trial_int >= sides:
            continue
        else:
            history.append(f"{trial_int:0{max_width}d}")

    return ",".join(history)
