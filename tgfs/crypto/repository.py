"""Decorator that adds transparent encryption to an ``IFileContentRepository``.

The wrapper intercepts the two relevant operations:

* :meth:`save` -- wraps the incoming plaintext ``UploadableFileMessage`` in
  an :class:`EncryptingFileMessage` and delegates to the inner repository.
  The encrypted ciphertext (header + chunks) is what actually lands in
  Telegram. The returned ``SentFileMessage`` list reflects ciphertext part
  sizes, which is what TGFS persists in its metadata.

* :meth:`get` -- translates the requested *plaintext* range
  ``[begin, end)`` into a *ciphertext* range, fetches the encrypted bytes
  via the inner repository, decrypts each chunk, and emits the requested
  plaintext slice. The on-disk header is read once per file and cached.

Everything else (file_desc API, directory API, WebDAV) keeps working
unchanged because the metadata still tracks parts by message id and size,
just with the ciphertext sizes substituted.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List, Optional

from tgfs.core.repository.interface import IFileContentRepository
from tgfs.crypto.cipher import (
    CHUNK_OVERHEAD,
    ChunkedAESGCM,
    chunk_to_ciphertext_offset,
    plaintext_offset_to_chunk,
)
from tgfs.crypto.header import HEADER_SIZE, FileHeader
from tgfs.crypto.kdf import derive_file_key
from tgfs.crypto.stream import EncryptingFileMessage
from tgfs.reqres import FileContent, SentFileMessage, UploadableFileMessage

if TYPE_CHECKING:
    # Only used for type hints; pulling the runtime symbol would drag in
    # telethon / pyrogram via tgfs.core.api.
    from tgfs.core.model import TGFSFileVersion

logger = logging.getLogger(__name__)

# Number of distinct files for which we cache parsed headers + derived keys.
# Each entry is tiny (~150 bytes); 1024 is plenty for most workloads.
_HEADER_CACHE_CAPACITY = 1024


class _HeaderCache:
    """Trivial bounded FIFO cache keyed by file version id.

    A full LRU would be marginally better, but FIFO is fine for read-mostly
    workloads and avoids pulling in another dependency.
    """

    def __init__(self, capacity: int = _HEADER_CACHE_CAPACITY) -> None:
        self._capacity = capacity
        self._store: dict[str, tuple[FileHeader, bytes]] = {}
        self._order: list[str] = []

    def get(self, version_id: str) -> Optional[tuple[FileHeader, bytes]]:
        return self._store.get(version_id)

    def put(self, version_id: str, header: FileHeader, file_key: bytes) -> None:
        if version_id in self._store:
            return
        if len(self._store) >= self._capacity:
            evict = self._order.pop(0)
            self._store.pop(evict, None)
        self._store[version_id] = (header, file_key)
        self._order.append(version_id)


class EncryptingFileContentRepository(IFileContentRepository):
    """Drop-in encryption decorator for :class:`IFileContentRepository`."""

    def __init__(
        self,
        inner: IFileContentRepository,
        master_key: bytes,
        *,
        chunk_size: int,
    ) -> None:
        self._inner = inner
        self._master_key = master_key
        self._chunk_size = chunk_size
        self._cache = _HeaderCache()

    # -- save --------------------------------------------------------------

    async def save(
        self, file_msg: UploadableFileMessage
    ) -> List[SentFileMessage]:
        # Build a fresh header (with a random salt) and derive the per-file
        # key. The header itself is written inline at the start of the
        # ciphertext stream.
        header = FileHeader.new(chunk_size=self._chunk_size)
        file_key = derive_file_key(self._master_key, header.file_salt)
        encrypted = EncryptingFileMessage.wrap(file_msg, file_key, header)
        logger.debug(
            "Encrypting file '%s': plaintext=%d ciphertext=%d chunks=%d",
            file_msg.name,
            file_msg.get_size(),
            encrypted.get_size(),
            (file_msg.get_size() + self._chunk_size - 1) // self._chunk_size,
        )
        return await self._inner.save(encrypted)

    # -- update ------------------------------------------------------------

    async def update(self, message_id: int, buffer: bytes, name: str) -> int:
        # ``update`` is used by the metadata layer to replace small payloads
        # (e.g. the metadata blob itself). We *do* want to encrypt these,
        # except when the caller is the metadata layer talking to itself --
        # but the file content repository is only invoked for file content,
        # so encrypting unconditionally is correct here.
        header = FileHeader.new(chunk_size=self._chunk_size)
        file_key = derive_file_key(self._master_key, header.file_salt)
        cipher = ChunkedAESGCM(
            file_key=file_key,
            file_salt=header.file_salt,
            chunk_size=header.chunk_size,
        )

        ciphertext_parts: list[bytes] = [header.serialize(file_key)]
        for chunk_index, start in enumerate(range(0, len(buffer), header.chunk_size)):
            chunk = buffer[start : start + header.chunk_size]
            ciphertext_parts.append(cipher.encrypt_chunk(chunk, chunk_index))
        ciphertext = b"".join(ciphertext_parts)
        return await self._inner.update(message_id, ciphertext, name)

    # -- get ---------------------------------------------------------------

    async def get(
        self,
        fv: "TGFSFileVersion",
        begin: int,
        end: int,
        name: str,
    ) -> FileContent:
        if fv.size <= 0:
            # Empty file -- the inner repo returns an empty iterator; we
            # forward that as-is. The plaintext range is meaningless here.

            async def empty():
                if False:
                    yield b""

            return empty()

        # Step 1: fetch and authenticate the header (60 B) once per file.
        header, file_key = await self._load_header(fv, name)
        cipher = ChunkedAESGCM(
            file_key=file_key,
            file_salt=header.file_salt,
            chunk_size=header.chunk_size,
        )

        # Step 2: translate the requested plaintext range to a ciphertext
        # range. ``end`` follows the same convention as the inner repo:
        # ``end < 0`` means "to the end of the file".
        plaintext_total = _plaintext_size_from_ciphertext(
            fv.size, header.chunk_size
        )
        if end < 0 or end > plaintext_total:
            end = plaintext_total
        if begin >= end:

            async def empty():
                if False:
                    yield b""

            return empty()

        start_chunk, start_offset_in_chunk = plaintext_offset_to_chunk(
            begin, header.chunk_size
        )
        # ``end`` is exclusive in TGFS's convention, so the last chunk we
        # need is the one containing byte ``end - 1``.
        last_chunk, _ = plaintext_offset_to_chunk(end - 1, header.chunk_size)
        n_chunks = last_chunk - start_chunk + 1

        ct_begin = HEADER_SIZE + chunk_to_ciphertext_offset(
            start_chunk, header.chunk_size
        )
        ct_end = HEADER_SIZE + chunk_to_ciphertext_offset(
            last_chunk + 1, header.chunk_size
        )
        # Clamp to the actual on-disk file size: the final chunk is typically
        # short (plaintext mod chunk_size), so its on-wire size is less than
        # ``chunk_size + CHUNK_OVERHEAD``.
        ct_end = min(ct_end, fv.size)

        logger.debug(
            "decrypt range plaintext=[%d,%d) chunks=[%d,%d] ciphertext=[%d,%d)",
            begin,
            end,
            start_chunk,
            last_chunk,
            ct_begin,
            ct_end,
        )

        inner_stream = await self._inner.get(fv, ct_begin, ct_end, name)
        return _decrypting_stream(
            inner_stream,
            cipher,
            start_chunk=start_chunk,
            n_chunks=n_chunks,
            trim_head=start_offset_in_chunk,
            trim_total=end - begin,
            chunk_size=header.chunk_size,
        )

    # -- internals ---------------------------------------------------------

    async def _load_header(
        self, fv: "TGFSFileVersion", name: str
    ) -> tuple[FileHeader, bytes]:
        """Fetch + authenticate the file header, with caching."""
        cached = self._cache.get(fv.id)
        if cached is not None:
            return cached

        # Fetch the first HEADER_SIZE bytes of ciphertext from the inner
        # repository -- it knows how to read across Telegram part boundaries
        # so we don't have to.
        stream = await self._inner.get(fv, 0, HEADER_SIZE, name)
        buf = bytearray()
        async for chunk in stream:
            buf += chunk
            if len(buf) >= HEADER_SIZE:
                break
        if len(buf) < HEADER_SIZE:
            raise ValueError(
                f"file '{name}' is too short to contain an encryption header "
                f"({len(buf)} < {HEADER_SIZE} bytes)"
            )

        raw_header = bytes(buf[:HEADER_SIZE])
        header = FileHeader.parse(raw_header)
        file_key = derive_file_key(self._master_key, header.file_salt)
        # Authenticate the header. If this fails the master key is wrong
        # or the header has been tampered with -- in either case we must
        # refuse to decrypt anything.
        FileHeader.verify(raw_header, file_key)

        self._cache.put(fv.id, header, file_key)
        return header, file_key


def _plaintext_size_from_ciphertext(ciphertext_size: int, chunk_size: int) -> int:
    """Invert :func:`ciphertext_size_for_plaintext`.

    Given the total ciphertext size including the header, return the original
    plaintext size. Used to translate "end of file" range requests.
    """
    if ciphertext_size <= HEADER_SIZE:
        return 0
    payload = ciphertext_size - HEADER_SIZE
    # Each full chunk on disk is chunk_size + CHUNK_OVERHEAD plaintext+meta.
    full_stride = chunk_size + CHUNK_OVERHEAD
    full_chunks, tail = divmod(payload, full_stride)
    if tail == 0:
        return full_chunks * chunk_size
    # The tail is one short chunk: tail = nonce + ct + tag where ct is the
    # short plaintext. So plaintext_in_tail = tail - CHUNK_OVERHEAD.
    if tail < CHUNK_OVERHEAD:
        raise ValueError("ciphertext size inconsistent with chunk layout")
    return full_chunks * chunk_size + (tail - CHUNK_OVERHEAD)


async def _decrypting_stream(
    inner_stream: FileContent,
    cipher: ChunkedAESGCM,
    *,
    start_chunk: int,
    n_chunks: int,
    trim_head: int,
    trim_total: int,
    chunk_size: int,
):
    """Reassemble ciphertext bytes into chunks, decrypt, and yield plaintext.

    Strategy:
      * All chunks except the *last* requested one are guaranteed to be
        ``stride`` bytes on disk (full chunk + overhead). We decrypt those
        eagerly as soon as the buffer holds enough bytes.
      * The final requested chunk may be short (when it coincides with the
        physical end of the file) OR full (when the requested range stops
        before EOF). We can only tell which by waiting for the inner stream
        to exhaust -- so we decrypt the tail exactly once, after the
        ``async for`` loop ends.
      * ``trim_head`` shaves the head of the first emitted chunk so that
        plaintext byte ``begin`` lands at position 0 of the output.
      * ``trim_total`` is the total number of plaintext bytes the caller
        asked for; we stop emitting once we have delivered that many.
    """
    stride = chunk_size + CHUNK_OVERHEAD
    buf = bytearray()
    chunk_index = start_chunk
    emitted = 0
    chunks_done = 0

    def _trim_and_count(plaintext: bytes) -> bytes:
        """Apply ``trim_head`` / ``trim_total`` and update ``emitted``.

        Returns the bytes that should be yielded (possibly empty). Mutates
        the enclosing ``trim_head`` / ``emitted`` via ``nonlocal``.
        """
        nonlocal trim_head, emitted
        if trim_head:
            plaintext = plaintext[trim_head:]
            trim_head = 0
        remaining = trim_total - emitted
        if len(plaintext) > remaining:
            plaintext = plaintext[:remaining]
        emitted += len(plaintext)
        return plaintext

    async for piece in inner_stream:
        if emitted >= trim_total:
            # We already have everything the caller asked for. Drain the
            # rest of the inner stream silently so the underlying tasks can
            # complete cleanly.
            continue
        buf += piece
        # Decrypt all full non-last chunks we can. The very last expected
        # chunk is deferred until the stream is fully consumed, because we
        # don't yet know whether it is short.
        while chunks_done < n_chunks - 1 and len(buf) >= stride:
            blob = bytes(buf[:stride])
            del buf[:stride]
            plaintext = cipher.decrypt_chunk(blob, chunk_index)
            chunk_index += 1
            chunks_done += 1
            out = _trim_and_count(plaintext)
            if out:
                yield out
            if emitted >= trim_total:
                return

    # Stream exhausted. Anything left in ``buf`` is the final requested
    # chunk -- its on-wire size is ``len(buf)``, which may equal ``stride``
    # (full chunk) or less (final chunk of the file).
    if chunks_done < n_chunks and buf and emitted < trim_total:
        plaintext = cipher.decrypt_chunk(bytes(buf), chunk_index)
        out = _trim_and_count(plaintext)
        if out:
            yield out
