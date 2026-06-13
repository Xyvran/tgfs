"""Deterministic, reversible encryption for metadata *path components*.

Unlike the per-upload document-name obfuscation in :mod:`tgfs.crypto.names`
(which uses a random nonce, so the same name encrypts differently every
time), the directory and file-reference names stored in the GitHub
metadata repo are *path identifiers*: the same logical name must always
map to the same on-repo path, or lookups and navigation would break and
duplicate folders would pile up. That rules out a randomized scheme, so we
use AES-SIV (RFC 5297) -- deterministic authenticated encryption -- keyed
by an HKDF-derived, domain-separated sub-key of the master key.

Wire format::

    "TGFSP1_" || base64url( AES-SIV(utf-8(name)) )

The output is filename-safe (base64url emits only ``[A-Za-z0-9_-]``) and
carries no ``/`` so it stays a single path segment. The prefix is distinct
from the content-name scheme (``TGFS1_``) so the loader can tell the two
apart and, crucially, so encrypted and legacy-plaintext entries can
coexist (mixed read): a name without the prefix is returned verbatim.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Distinct HKDF info so the path-name key cannot collide with the per-file
# content keys or the random-nonce document-name key.
_HKDF_INFO = b"tgfs-path-name-key-v1"

# Prefix tagging a repo path component as TGFS-encrypted.
PATH_NAME_PREFIX = "TGFSP1_"


class PathNameEncryptionError(ValueError):
    """Raised when an encrypted path name cannot be decoded or authenticated."""


def derive_path_name_key(master_key: bytes) -> bytes:
    """Derive a 64-byte AES-256-SIV key, domain-separated from other keys."""
    if len(master_key) != 32:
        raise ValueError(f"master key must be 32 bytes, got {len(master_key)}")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b"",
        info=_HKDF_INFO,
    )
    return hkdf.derive(master_key)


def is_encrypted_path_name(name: str) -> bool:
    """Return whether ``name`` carries the TGFS encrypted-path prefix."""
    return name.startswith(PATH_NAME_PREFIX)


def encrypt_path_name(key: bytes, plaintext: str) -> str:
    """Deterministically encrypt a single path component.

    The same ``(key, plaintext)`` always yields the same output, so the
    result is a stable storage identifier.
    """
    siv = AESSIV(key)
    blob = siv.encrypt(plaintext.encode("utf-8"), None)
    return PATH_NAME_PREFIX + base64.urlsafe_b64encode(blob).rstrip(b"=").decode(
        "ascii"
    )


def decrypt_path_name(key: bytes, encrypted: str) -> str:
    """Reverse :func:`encrypt_path_name`."""
    if not encrypted.startswith(PATH_NAME_PREFIX):
        raise PathNameEncryptionError("not a TGFS-encrypted path name")
    body = encrypted[len(PATH_NAME_PREFIX) :]
    # urlsafe_b64decode needs proper padding; encrypt strips it for
    # compactness, so re-pad here.
    body += "=" * (-len(body) % 4)
    try:
        blob = base64.urlsafe_b64decode(body.encode("ascii"))
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise PathNameEncryptionError(
            f"invalid base64 in encrypted path name: {exc}"
        ) from exc
    siv = AESSIV(key)
    try:
        plain = siv.decrypt(blob, None)
    except Exception as exc:
        raise PathNameEncryptionError("path name authentication failed") from exc
    return plain.decode("utf-8")
