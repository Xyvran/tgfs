"""Integration tests for :mod:`tgfs.crypto.stream` and
:mod:`tgfs.crypto.repository`.

These tests deliberately do not touch Telegram. They drive the
encryption/decryption pipeline with a fake :class:`IFileContentRepository`
that stores ciphertext in memory, which is sufficient to validate:

  * upload/download round-trip across multiple crypto-chunks
  * range requests at arbitrary plaintext offsets
  * detection of corrupted ciphertext
  * detection of a wrong master key
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

import pytest

from tgfs.core.repository.interface import IFileContentRepository
from tgfs.crypto.cipher import CHUNK_OVERHEAD
from tgfs.crypto.header import HEADER_SIZE
from tgfs.crypto.repository import EncryptingFileContentRepository
from tgfs.reqres import (
    FileContent,
    FileMessageFromBuffer,
    SentFileMessage,
    UploadableFileMessage,
)


# --- in-memory fake backend -------------------------------------------------


@dataclass
class _FakeFileVersion:
    """Stand-in for ``TGFSFileVersion`` good enough for the repository.

    Only ``id``, ``size``, ``message_ids``, and ``part_sizes`` are consulted.
    """

    id: str
    size: int
    message_ids: List[int] = field(default_factory=list)
    part_sizes: List[int] = field(default_factory=list)


class _InMemoryRepo(IFileContentRepository):
    """An ``IFileContentRepository`` that stores ciphertext in a dict.

    A "part" of the file is one message id. To make range tests interesting,
    we always store the file as a single part -- this matches small files
    in tgfs (anything < 2 GB) and exercises the chunk-level range logic in
    the encrypting wrapper.
    """

    def __init__(self, part_size: int = 10**9) -> None:
        self._files: dict[int, bytes] = {}
        self._next_msg_id = 1000
        self._part_size = part_size

    async def save(
        self, file_msg: UploadableFileMessage
    ) -> List[SentFileMessage]:
        # Read the whole ciphertext into memory in chunks, mimicking what
        # the real uploader does. We force several reads of varied size to
        # stress the wrapper's buffering.
        await file_msg.open()
        try:
            buf = bytearray()
            for read_size in (7, 4096, 8192, 1024 * 1024):
                while True:
                    piece = await file_msg.read(read_size)
                    if not piece:
                        break
                    buf += piece
                    if len(buf) >= file_msg.get_size():
                        break
                if len(buf) >= file_msg.get_size():
                    break
        finally:
            await file_msg.close()

        ciphertext = bytes(buf)
        msg_id = self._next_msg_id
        self._next_msg_id += 1
        self._files[msg_id] = ciphertext
        return [SentFileMessage(message_id=msg_id, size=len(ciphertext))]

    async def get(
        self, fv, begin: int, end: int, name: str
    ) -> FileContent:
        # Single-part files only in this fake, so use the first message id.
        ciphertext = self._files[fv.message_ids[0]]
        if end < 0:
            end = len(ciphertext)

        async def stream():
            # Emit in small, oddly-sized pieces to make sure the decrypting
            # consumer handles arbitrary boundaries.
            i = begin
            for step in (3, 17, 1024, 8192):
                if i >= end:
                    break
                slice_end = min(i + step, end)
                yield ciphertext[i:slice_end]
                i = slice_end
            if i < end:
                yield ciphertext[i:end]

        return stream()

    async def update(self, message_id: int, buffer: bytes, name: str) -> int:
        self._files[message_id] = buffer
        return message_id


def _make_repo(master_key: bytes = b"\x77" * 32, chunk_size: int = 4096):
    return EncryptingFileContentRepository(
        _InMemoryRepo(),
        master_key=master_key,
        chunk_size=chunk_size,
    )


async def _save_and_get_fv(repo, data: bytes):
    file_msg = FileMessageFromBuffer.new(buffer=data, name="test.bin")
    sent = await repo.save(file_msg)
    fv = _FakeFileVersion(
        id="v1",
        size=sum(m.size for m in sent),
        message_ids=[m.message_id for m in sent],
        part_sizes=[m.size for m in sent],
    )
    return fv


async def _collect(stream) -> bytes:
    buf = bytearray()
    async for piece in stream:
        buf += piece
    return bytes(buf)


# --- round-trip tests ------------------------------------------------------


@pytest.mark.parametrize(
    "size",
    [
        0,
        1,
        100,
        4095,
        4096,
        4097,
        4096 * 3,
        4096 * 10 + 123,
        4096 * 50 + 1,
    ],
)
async def test_full_round_trip(size: int) -> None:
    repo = _make_repo(chunk_size=4096)
    plaintext = os.urandom(size)
    fv = await _save_and_get_fv(repo, plaintext)

    out = await _collect(await repo.get(fv, 0, -1, "test.bin"))
    assert out == plaintext


async def test_ciphertext_size_matches_formula() -> None:
    repo = _make_repo(chunk_size=4096)
    plaintext = os.urandom(4096 * 5 + 17)
    fv = await _save_and_get_fv(repo, plaintext)
    # Ciphertext = header + 6 chunks (5 full + 1 short), each with overhead.
    expected = HEADER_SIZE + len(plaintext) + 6 * CHUNK_OVERHEAD
    assert fv.size == expected


# --- range request tests ---------------------------------------------------


async def test_range_request_within_first_chunk() -> None:
    repo = _make_repo(chunk_size=4096)
    plaintext = os.urandom(4096 * 5)
    fv = await _save_and_get_fv(repo, plaintext)
    out = await _collect(await repo.get(fv, 100, 200, "test.bin"))
    assert out == plaintext[100:200]


async def test_range_request_spanning_chunk_boundary() -> None:
    repo = _make_repo(chunk_size=4096)
    plaintext = os.urandom(4096 * 5)
    fv = await _save_and_get_fv(repo, plaintext)
    # 4090..4106 spans the boundary between chunk 0 and chunk 1.
    out = await _collect(await repo.get(fv, 4090, 4106, "test.bin"))
    assert out == plaintext[4090:4106]


async def test_range_request_across_many_chunks() -> None:
    repo = _make_repo(chunk_size=4096)
    plaintext = os.urandom(4096 * 10)
    fv = await _save_and_get_fv(repo, plaintext)
    # Pick a range that touches 4 chunks.
    begin, end = 4096 * 2 + 50, 4096 * 6 - 50
    out = await _collect(await repo.get(fv, begin, end, "test.bin"))
    assert out == plaintext[begin:end]


async def test_range_request_to_end_of_file() -> None:
    repo = _make_repo(chunk_size=4096)
    plaintext = os.urandom(4096 * 3 + 100)
    fv = await _save_and_get_fv(repo, plaintext)
    out = await _collect(await repo.get(fv, 1234, -1, "test.bin"))
    assert out == plaintext[1234:]


async def test_range_request_last_byte() -> None:
    repo = _make_repo(chunk_size=4096)
    plaintext = os.urandom(4096 * 3 + 100)
    fv = await _save_and_get_fv(repo, plaintext)
    out = await _collect(
        await repo.get(fv, len(plaintext) - 1, len(plaintext), "test.bin")
    )
    assert out == plaintext[-1:]


# --- security tests --------------------------------------------------------


async def test_wrong_master_key_fails_header_verify() -> None:
    write_repo = _make_repo(master_key=b"\x77" * 32, chunk_size=4096)
    fv = await _save_and_get_fv(write_repo, os.urandom(8192))

    # New repo with a *different* master key, same ciphertext backend.
    read_repo = EncryptingFileContentRepository(
        write_repo._inner,
        master_key=b"\x99" * 32,
        chunk_size=4096,
    )
    with pytest.raises(Exception):  # InvalidHeaderError, but imported indirectly
        await _collect(await read_repo.get(fv, 0, -1, "test.bin"))


async def test_corrupted_ciphertext_chunk_detected() -> None:
    repo = _make_repo(chunk_size=4096)
    plaintext = os.urandom(4096 * 3)
    fv = await _save_and_get_fv(repo, plaintext)

    # Flip a byte in the middle of the first chunk's ciphertext, leaving
    # the header intact.
    inner: _InMemoryRepo = repo._inner  # type: ignore[assignment]
    msg_id = fv.message_ids[0]
    blob = bytearray(inner._files[msg_id])
    blob[HEADER_SIZE + 50] ^= 0x01
    inner._files[msg_id] = bytes(blob)

    with pytest.raises(Exception):
        await _collect(await repo.get(fv, 0, -1, "test.bin"))


async def test_empty_file_round_trip() -> None:
    repo = _make_repo(chunk_size=4096)
    fv = await _save_and_get_fv(repo, b"")
    out = await _collect(await repo.get(fv, 0, -1, "test.bin"))
    assert out == b""
