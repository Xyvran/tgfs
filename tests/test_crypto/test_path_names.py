"""Tests for :mod:`tgfs.crypto.path_names`.

Covers the round-trip property, the *deterministic* property that makes the
ciphertext usable as a stable path identifier (same plaintext -> same
output, unlike the randomized document-name scheme), authentication
(wrong key / tampering), filename-safety, and the mixed-read prefix helper.
"""

from __future__ import annotations

import pytest

from tgfs.crypto.path_names import (
    PATH_NAME_PREFIX,
    PathNameEncryptionError,
    decrypt_path_name,
    derive_path_name_key,
    encrypt_path_name,
    is_encrypted_path_name,
)


def _key() -> bytes:
    return derive_path_name_key(b"\x42" * 32)


# --- key derivation --------------------------------------------------------


def test_derive_key_length_is_64() -> None:
    # 64 bytes -> AES-256-SIV
    assert len(_key()) == 64


def test_derive_key_rejects_short_master() -> None:
    with pytest.raises(ValueError):
        derive_path_name_key(b"\x00" * 16)


def test_derive_key_is_deterministic() -> None:
    assert derive_path_name_key(b"\x01" * 32) == derive_path_name_key(b"\x01" * 32)


def test_derive_key_is_domain_separated() -> None:
    from tgfs.crypto.names import derive_name_key

    master = b"\x07" * 32
    # The path-name key must differ from the document-name key (truncate the
    # 64-byte path key for comparison with the 32-byte name key).
    assert derive_path_name_key(master)[:32] != derive_name_key(master)


# --- round-trip + determinism ----------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "Filme",
        "Better Call Saul",
        "Van Damme - Born to Kill (2024).mp4",
        "Ümläute und Leerzeichen",
        "a/b weird",  # a slash in the logical name
        "x",
        "." * 3,
    ],
)
def test_round_trip(name: str) -> None:
    key = _key()
    enc = encrypt_path_name(key, name)
    assert decrypt_path_name(key, enc) == name


def test_is_deterministic() -> None:
    key = _key()
    assert encrypt_path_name(key, "Serien") == encrypt_path_name(key, "Serien")


def test_output_is_prefixed_and_filename_safe() -> None:
    key = _key()
    enc = encrypt_path_name(key, "Van Damme - Born to Kill (2024).mp4")
    assert enc.startswith(PATH_NAME_PREFIX)
    assert is_encrypted_path_name(enc)
    # single path segment, filename-safe base64url alphabet only
    body = enc[len(PATH_NAME_PREFIX):]
    assert "/" not in enc and "+" not in enc and "=" not in enc
    assert all(c.isalnum() or c in "-_" for c in body)


# --- authentication / errors ----------------------------------------------


def test_wrong_key_fails_authentication() -> None:
    enc = encrypt_path_name(_key(), "secret-folder")
    other = derive_path_name_key(b"\x99" * 32)
    with pytest.raises(PathNameEncryptionError):
        decrypt_path_name(other, enc)


def test_tampered_ciphertext_fails() -> None:
    key = _key()
    enc = encrypt_path_name(key, "secret-folder")
    tampered = enc[:-1] + ("A" if enc[-1] != "A" else "B")
    with pytest.raises(PathNameEncryptionError):
        decrypt_path_name(key, tampered)


def test_decrypt_rejects_non_prefixed() -> None:
    with pytest.raises(PathNameEncryptionError):
        decrypt_path_name(_key(), "Filme")  # plaintext, no prefix


def test_is_encrypted_path_name() -> None:
    assert is_encrypted_path_name(PATH_NAME_PREFIX + "abc")
    assert not is_encrypted_path_name("Filme")
    assert not is_encrypted_path_name("movie.mp4.123")
