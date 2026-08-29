import asyncio
import errno
import logging
import os
import tempfile
from typing import AsyncIterator, Optional

from tgfs.core import Ops

logger = logging.getLogger(__name__)

SEEK_DATA = getattr(os, "SEEK_DATA", 3)
SEEK_HOLE = getattr(os, "SEEK_HOLE", 4)

# A forward jump shorter than this is bridged by reading through the open
# stream. Re-opening costs a Telegram round trip, reading through costs
# bandwidth we have already paid for -- one mebibyte is where the two meet
# for the clients that leave small gaps (they typically skip a few kibibytes).
SEEK_FORWARD_THRESHOLD = 1024 * 1024

# How much of the spooled upload we hand to the uploader at a time.
SPOOL_READ_CHUNK = 1024 * 1024


class Handle:
    """Shared behaviour of the objects handed back to the SFTP layer."""

    @property
    def size(self) -> int:
        raise NotImplementedError

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Answer the sparse-region probing done on a transfer's source.

        Before copying, an SFTP client may walk the source with
        ``SEEK_DATA``/``SEEK_HOLE`` to find out which regions it can skip.
        Nothing stored here is ever sparse, so report a single solid data
        region spanning the whole file. Ordinary seeking is not offered --
        reads carry their own offset.
        """
        size = self.size
        if whence in (SEEK_DATA, SEEK_HOLE):
            if offset >= size:
                raise OSError(errno.ENXIO, os.strerror(errno.ENXIO))
            return offset if whence == SEEK_DATA else size
        raise OSError(errno.ESPIPE, os.strerror(errno.ESPIPE))


class ReadHandle(Handle):
    """Serves random-access SFTP reads from a one-shot download stream.

    ``Ops.download`` yields the file from a given offset onwards and cannot
    seek, while SFTP clients read at arbitrary offsets and pipeline their
    requests. So we keep one stream plus the offset it has reached: reads
    that continue where the last one stopped -- the overwhelming majority --
    are served straight from it, and anything else re-opens the stream at
    the requested offset, which is exactly what a WebDAV range request does.
    """

    def __init__(self, ops: Ops, path: str, name: str, size: int):
        self._ops = ops
        self._path = path
        self._name = name
        self._size = size

        self._stream: Optional[AsyncIterator[bytes]] = None
        self._pos = 0
        self._buffer = bytearray()
        self._lock = asyncio.Lock()

    @property
    def size(self) -> int:
        return self._size

    async def read(self, offset: int, size: int) -> bytes:
        """Return up to ``size`` bytes at ``offset``; empty bytes mean EOF."""
        if size <= 0 or offset >= self._size:
            return b""

        async with self._lock:
            if self._stream is None or offset < self._pos:
                await self._reopen(offset)
            elif offset > self._pos:
                gap = offset - self._pos
                if gap > SEEK_FORWARD_THRESHOLD:
                    await self._reopen(offset)
                elif len(await self._consume(gap)) < gap:
                    # The gap ran past the end of the file.
                    return b""

            return await self._consume(size)

    async def close(self) -> None:
        async with self._lock:
            await self._close_stream()
            self._buffer = bytearray()

    async def _reopen(self, offset: int) -> None:
        await self._close_stream()
        self._buffer = bytearray()
        self._pos = offset
        self._stream = await self._ops.download(self._path, offset, -1, self._name)

    async def _close_stream(self) -> None:
        stream, self._stream = self._stream, None
        aclose = getattr(stream, "aclose", None)
        if aclose is None:
            return
        try:
            await aclose()
        except Exception as ex:  # pragma: no cover - best effort cleanup
            logger.debug("Failed to close download stream for %s: %s", self._path, ex)

    async def _consume(self, count: int) -> bytes:
        while len(self._buffer) < count:
            chunk = await self._next_chunk()
            if not chunk:
                break
            self._buffer.extend(chunk)

        data = bytes(self._buffer[:count])
        del self._buffer[: len(data)]
        self._pos += len(data)
        return data

    async def _next_chunk(self) -> bytes:
        if self._stream is None:
            return b""
        try:
            return await self._stream.__anext__()
        except StopAsyncIteration:
            return b""


class WriteHandle(Handle):
    """Buffers an SFTP upload until its total size is known.

    Telegram uploads need the size up front and SFTP never announces it, so
    the payload is spooled -- in memory up to ``spool_max_bytes``, on disk
    beyond that -- and only committed once the client closes the handle.
    Buffering also makes out-of-order and sparse writes work, since the
    spool can simply be seeked.
    """

    def __init__(
        self,
        ops: Ops,
        path: str,
        spool_max_bytes: int,
        spool_dir: Optional[str] = None,
    ):
        self._ops = ops
        self._path = path
        self._spool = tempfile.SpooledTemporaryFile(
            max_size=spool_max_bytes, dir=spool_dir
        )
        self._size = 0
        self._dirty = False
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def path(self) -> str:
        return self._path

    @property
    def size(self) -> int:
        return self._size

    async def write(self, offset: int, data: bytes) -> None:
        async with self._lock:
            if self._closed:
                raise ValueError("write on a closed handle")
            await asyncio.to_thread(self._write_sync, offset, data)

    async def close(self) -> None:
        """Commit the buffered payload as a new version of the file."""
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                if self._dirty:
                    await self._ops.upload_from_stream(
                        self._iter_spool(), self._size, self._path
                    )
            finally:
                await asyncio.to_thread(self._spool.close)

    async def abort(self) -> None:
        """Drop the buffered payload without touching the stored file."""
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            await asyncio.to_thread(self._spool.close)

    def _write_sync(self, offset: int, data: bytes) -> None:
        self._spool.seek(offset)
        self._spool.write(data)
        self._size = max(self._size, offset + len(data))
        self._dirty = True

    async def _iter_spool(self) -> AsyncIterator[bytes]:
        await asyncio.to_thread(self._spool.seek, 0)
        remaining = self._size
        while remaining > 0:
            chunk = await asyncio.to_thread(
                self._spool.read, min(SPOOL_READ_CHUNK, remaining)
            )
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk
