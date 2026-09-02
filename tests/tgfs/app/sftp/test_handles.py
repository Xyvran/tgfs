import errno
import os

import pytest
from tgfs.app.sftp.handles import (
    SEEK_DATA,
    SEEK_FORWARD_THRESHOLD,
    SEEK_HOLE,
    ReadHandle,
    WriteHandle,
)
from tgfs.core import Ops

CONTENT = bytes(range(256)) * 64  # 16 KiB of easily verifiable data


def make_ops(mocker, content: bytes = CONTENT, chunk_size: int = 1024):
    """An ``Ops`` mock whose ``download`` streams ``content`` from an offset."""
    ops = mocker.Mock(spec=Ops)

    async def download(path, begin, end, as_name):
        stop = len(content) if end < 0 else min(len(content), end + 1)

        async def stream():
            for start in range(begin, stop, chunk_size):
                yield content[start : min(start + chunk_size, stop)]

        return stream()

    ops.download = mocker.AsyncMock(side_effect=download)
    return ops


class TestReadHandle:
    @pytest.fixture
    def ops(self, mocker):
        return make_ops(mocker)

    @pytest.fixture
    def handle(self, ops):
        return ReadHandle(ops, "/file.bin", "file.bin", len(CONTENT))

    async def test_reads_sequentially_across_chunks(self, handle, ops):
        received = b""
        offset = 0
        while chunk := await handle.read(offset, 3000):
            received += chunk
            offset += len(chunk)

        assert received == CONTENT
        assert ops.download.await_count == 1

    async def test_read_returns_at_most_the_requested_size(self, handle):
        assert await handle.read(0, 10) == CONTENT[:10]

    async def test_read_past_the_end_signals_eof(self, handle):
        assert await handle.read(len(CONTENT), 10) == b""

    async def test_read_of_zero_bytes_is_empty(self, handle):
        assert await handle.read(0, 0) == b""

    async def test_backward_seek_reopens_the_stream(self, handle, ops):
        await handle.read(0, 4096)
        assert await handle.read(100, 16) == CONTENT[100:116]

        assert ops.download.await_count == 2
        assert ops.download.await_args.args[1] == 100

    async def test_small_forward_gap_reads_through(self, handle, ops):
        await handle.read(0, 16)
        assert await handle.read(2048, 16) == CONTENT[2048:2064]

        assert ops.download.await_count == 1

    async def test_large_forward_gap_reopens_the_stream(self, mocker):
        content = b"x" * (4 * SEEK_FORWARD_THRESHOLD)
        ops = make_ops(mocker, content, chunk_size=SEEK_FORWARD_THRESHOLD)
        handle = ReadHandle(ops, "/big.bin", "big.bin", len(content))

        await handle.read(0, 16)
        offset = 2 * SEEK_FORWARD_THRESHOLD
        assert len(await handle.read(offset, 16)) == 16

        assert ops.download.await_count == 2
        assert ops.download.await_args.args[1] == offset

    async def test_close_is_idempotent(self, handle):
        await handle.read(0, 16)
        await handle.close()
        await handle.close()


class TestSparseRangeProbing:
    """Clients walk a transfer source with SEEK_DATA/SEEK_HOLE first."""

    @pytest.fixture
    def handle(self, mocker):
        return ReadHandle(make_ops(mocker), "/file.bin", "file.bin", len(CONTENT))

    def test_the_whole_file_reads_as_one_data_region(self, handle):
        assert handle.seek(0, SEEK_DATA) == 0
        assert handle.seek(0, SEEK_HOLE) == len(CONTENT)

    def test_probing_from_the_middle(self, handle):
        assert handle.seek(100, SEEK_DATA) == 100
        assert handle.seek(100, SEEK_HOLE) == len(CONTENT)

    def test_probing_past_the_end_reports_no_more_data(self, handle):
        with pytest.raises(OSError) as excinfo:
            handle.seek(len(CONTENT), SEEK_DATA)

        assert excinfo.value.errno == errno.ENXIO

    def test_ordinary_seeking_is_not_offered(self, handle):
        with pytest.raises(OSError) as excinfo:
            handle.seek(0, os.SEEK_SET)

        assert excinfo.value.errno == errno.ESPIPE


class TestWriteHandle:
    @pytest.fixture
    def ops(self, mocker):
        """``Ops`` mock that drains the upload stream the way the real one does."""
        ops = mocker.Mock(spec=Ops)
        ops.uploaded = {}

        async def upload_from_stream(stream, size, remote):
            data = b"".join([chunk async for chunk in stream])
            assert len(data) == size
            ops.uploaded[remote] = data

        async def upload_from_msg(file_msg, remote):
            chunks = []
            while chunk := await file_msg.read(64 * 1024):
                chunks.append(chunk)
            data = b"".join(chunks)
            ops.uploaded[remote] = data

        ops.upload_from_stream = mocker.AsyncMock(side_effect=upload_from_stream)
        ops.upload_from_msg = mocker.AsyncMock(side_effect=upload_from_msg)
        return ops

    async def test_sequential_writes_are_uploaded_in_order(self, ops):
        handle = WriteHandle(ops, "/file.bin", spool_max_bytes=1024)
        await handle.write(0, b"hello ")
        await handle.write(6, b"world")
        await handle.close()

        assert ops.uploaded == {"/file.bin": b"hello world"}

    async def test_out_of_order_writes_land_at_their_offset(self, ops):
        handle = WriteHandle(ops, "/file.bin", spool_max_bytes=1024)
        await handle.write(6, b"world")
        await handle.write(0, b"hello ")
        await handle.close()

        assert ops.uploaded["/file.bin"] == b"hello world"

    async def test_sparse_writes_are_zero_filled(self, ops):
        handle = WriteHandle(ops, "/file.bin", spool_max_bytes=1024)
        await handle.write(4, b"tail")
        await handle.close()

        assert ops.uploaded["/file.bin"] == b"\x00\x00\x00\x00tail"

    async def test_payload_larger_than_the_spool_is_uploaded_intact(self, ops):
        payload = bytes(range(256)) * 512  # 128 KiB, well past the spool limit
        handle = WriteHandle(ops, "/file.bin", spool_max_bytes=1024)
        await handle.write(0, payload)
        await handle.close()

        assert ops.uploaded["/file.bin"] == payload

    async def test_close_without_any_write_uploads_nothing(self, ops):
        handle = WriteHandle(ops, "/file.bin", spool_max_bytes=1024)
        await handle.close()

        ops.upload_from_stream.assert_not_awaited()

    async def test_abort_uploads_nothing(self, ops):
        handle = WriteHandle(ops, "/file.bin", spool_max_bytes=1024)
        await handle.write(0, b"partial")
        await handle.abort()

        ops.upload_from_stream.assert_not_awaited()

    async def test_close_after_abort_does_not_upload(self, ops):
        handle = WriteHandle(ops, "/file.bin", spool_max_bytes=1024)
        await handle.write(0, b"partial")
        await handle.abort()
        await handle.close()

        ops.upload_from_stream.assert_not_awaited()

    async def test_write_after_close_is_rejected(self, ops):
        handle = WriteHandle(ops, "/file.bin", spool_max_bytes=1024)
        await handle.close()

        with pytest.raises(ValueError):
            await handle.write(0, b"late")
