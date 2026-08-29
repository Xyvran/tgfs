"""The block cache in front of downloads, and the read-ahead behind it."""

import asyncio
from typing import List, Optional, Sequence, cast

import pytest

from tgfs.config import TransferConfig
from tgfs.core.api.message import MessageApi
from tgfs.core.api.message import message_broker as mb
from tgfs.reqres import (
    Document,
    DownloadFileReq,
    DownloadFileResp,
    GetMessagesResp,
    MessageResp,
)
from tgfs.telegram.interface import ITDLibClient, TDLibApi
from tgfs.utils.chunk_cache import ChunkCache
from tgfs.utils.message_cache import global_message_cache

CHANNEL = 777
MESSAGE = 42
BLOCK = 512 * 1024  # config-test.yaml sets download.chunk_size_kb to 512
FILE_SIZE = BLOCK * 3 + 100  # three full blocks and a short one


def content(size: int = FILE_SIZE) -> bytes:
    return bytes(range(256)) * (size // 256) + bytes(range(size % 256))


CONTENT = content()


class FakeBot:
    """Serves ranges out of one in-memory document."""

    def __init__(self, size: int = FILE_SIZE):
        self.size = size
        self.ranges: List[tuple] = []
        self.truncate_after: Optional[int] = None

    async def get_messages(self, req) -> GetMessagesResp:
        return GetMessagesResp(
            [
                MessageResp(
                    message_id=mid,
                    text="",
                    document=Document(
                        size=self.size,
                        id=1,
                        access_hash=1,
                        file_reference=b"ref",
                        mime_type="application/octet-stream",
                    ),
                )
                for mid in req.message_ids
            ]
        )

    async def download_file(self, req: DownloadFileReq) -> DownloadFileResp:
        self.ranges.append((req.begin, req.end))
        payload = CONTENT[req.begin : req.end + 1]
        if self.truncate_after is not None:
            payload = payload[: self.truncate_after]

        async def chunks():
            for start in range(0, len(payload), BLOCK):
                yield payload[start : start + BLOCK]

        return DownloadFileResp(chunks=chunks(), size=len(payload))

    async def get_me(self):  # pragma: no cover - only used on failure paths
        raise NotImplementedError


@pytest.fixture(autouse=True)
def fast_broker(mocker):
    mocker.patch.object(mb, "DELAY", 0.01)


@pytest.fixture(autouse=True)
def clean_message_cache():
    global_message_cache.clear()
    yield
    global_message_cache.clear()


@pytest.fixture
def bot() -> FakeBot:
    return FakeBot()


@pytest.fixture
def cache() -> ChunkCache:
    return ChunkCache(64 * 1024 * 1024)


@pytest.fixture
def api(bot, cache, mocker) -> MessageApi:
    mocker.patch("tgfs.core.api.message.chunk_cache", return_value=cache)
    mocker.patch(
        "tgfs.core.api.message._transfer",
        return_value=TransferConfig.from_dict({"chunk_cache_readahead": 0}),
    )
    return MessageApi(TDLibApi(bots=cast(Sequence[ITDLibClient], [bot])), CHANNEL)


async def read(api: MessageApi, begin: int, end: int) -> bytes:
    resp = await api.download_file(MESSAGE, begin, end)
    return b"".join([chunk async for chunk in resp.chunks])


class TestCorrectness:
    @pytest.mark.asyncio
    async def test_the_requested_bytes_come_back_exactly(self, api):
        assert await read(api, 0, 99) == CONTENT[:100]

    @pytest.mark.asyncio
    async def test_a_range_spanning_several_blocks(self, api):
        begin, end = BLOCK - 10, 2 * BLOCK + 10
        assert await read(api, begin, end) == CONTENT[begin : end + 1]

    @pytest.mark.asyncio
    async def test_a_range_ending_in_the_short_final_block(self, api):
        begin = 3 * BLOCK - 5
        assert await read(api, begin, FILE_SIZE - 1) == CONTENT[begin:FILE_SIZE]

    @pytest.mark.asyncio
    async def test_an_end_past_the_document_is_clamped(self, api):
        assert await read(api, FILE_SIZE - 50, FILE_SIZE + 1000) == CONTENT[-50:]

    @pytest.mark.asyncio
    async def test_reading_the_whole_file(self, api):
        assert await read(api, 0, FILE_SIZE - 1) == CONTENT


class TestReuse:
    @pytest.mark.asyncio
    async def test_a_repeated_read_costs_no_download(self, api, bot):
        await read(api, 0, 99)
        before = len(bot.ranges)

        assert await read(api, 0, 99) == CONTENT[:100]
        assert len(bot.ranges) == before

    @pytest.mark.asyncio
    async def test_small_sequential_reads_share_one_fetch(self, api, bot):
        """The SFTP pattern: a file walked in small reads."""
        for offset in range(0, 64 * 1024, 8 * 1024):
            await read(api, offset, offset + 8 * 1024 - 1)

        assert len(bot.ranges) == 1

    @pytest.mark.asyncio
    async def test_seeking_backwards_is_free(self, api, bot):
        await read(api, 0, BLOCK - 1)
        before = len(bot.ranges)

        assert await read(api, 10, 20) == CONTENT[10:21]
        assert len(bot.ranges) == before

    @pytest.mark.asyncio
    async def test_only_the_missing_blocks_are_fetched(self, api, bot):
        await read(api, 0, 10)  # pulls block 0
        bot.ranges.clear()

        await read(api, 0, 2 * BLOCK - 1)  # needs blocks 0 and 1

        assert bot.ranges == [(BLOCK, 2 * BLOCK - 1)]

    @pytest.mark.asyncio
    async def test_fetches_are_whole_blocks(self, api, bot):
        """A partial block would be useless to the next reader."""
        await read(api, 10, 20)

        assert bot.ranges == [(0, BLOCK - 1)]


class TestSafety:
    @pytest.mark.asyncio
    async def test_a_truncated_stream_is_not_cached(self, api, bot, cache):
        """A short read must never be served later as a whole block."""
        bot.truncate_after = 100

        await read(api, 0, BLOCK - 1)

        assert not cache.contains((CHANNEL, MESSAGE, 0))

    @pytest.mark.asyncio
    async def test_the_short_final_block_is_cached(self, api, bot, cache):
        """Short because the file ends there, which is a complete block."""
        await read(api, 3 * BLOCK, FILE_SIZE - 1)

        assert cache.contains((CHANNEL, MESSAGE, 3))

    @pytest.mark.asyncio
    async def test_a_disabled_cache_leaves_the_range_untouched(self, bot, mocker):
        mocker.patch(
            "tgfs.core.api.message.chunk_cache", return_value=ChunkCache(0)
        )
        api = MessageApi(
            TDLibApi(bots=cast(Sequence[ITDLibClient], [bot])), CHANNEL
        )

        assert await read(api, 10, 20) == CONTENT[10:21]
        assert bot.ranges == [(10, 20)]

    @pytest.mark.asyncio
    async def test_blocks_of_different_channels_do_not_mix(self, bot, cache, mocker):
        """Mirror copies live in their own channels under their own ids."""
        mocker.patch("tgfs.core.api.message.chunk_cache", return_value=cache)
        mocker.patch(
            "tgfs.core.api.message._transfer",
            return_value=TransferConfig.from_dict({"chunk_cache_readahead": 0}),
        )
        first = MessageApi(TDLibApi(bots=cast(Sequence[ITDLibClient], [bot])), 1)
        second = MessageApi(TDLibApi(bots=cast(Sequence[ITDLibClient], [bot])), 2)

        await read(first, 0, 10)
        bot.ranges.clear()
        await read(second, 0, 10)

        assert bot.ranges == [(0, BLOCK - 1)]


class TestReadAhead:
    @pytest.fixture
    def api(self, bot, cache, mocker) -> MessageApi:
        mocker.patch("tgfs.core.api.message.chunk_cache", return_value=cache)
        mocker.patch(
            "tgfs.core.api.message._transfer",
            return_value=TransferConfig.from_dict({"chunk_cache_readahead": 2}),
        )
        return MessageApi(
            TDLibApi(bots=cast(Sequence[ITDLibClient], [bot])), CHANNEL
        )

    @pytest.mark.asyncio
    async def test_the_next_blocks_are_pulled_in(self, api, cache):
        await read(api, 0, 10)
        await asyncio.sleep(0.05)

        assert cache.contains((CHANNEL, MESSAGE, 1))
        assert cache.contains((CHANNEL, MESSAGE, 2))

    @pytest.mark.asyncio
    async def test_the_following_read_is_then_free(self, api, bot):
        await read(api, 0, 10)
        await asyncio.sleep(0.05)
        bot.ranges.clear()

        assert await read(api, BLOCK, BLOCK + 10) == CONTENT[BLOCK : BLOCK + 11]
        assert bot.ranges == []

    @pytest.mark.asyncio
    async def test_it_stops_at_the_end_of_the_document(self, api, cache):
        await read(api, 3 * BLOCK, FILE_SIZE - 1)
        await asyncio.sleep(0.05)

        assert not cache.contains((CHANNEL, MESSAGE, 4))

    @pytest.mark.asyncio
    async def test_a_failing_read_ahead_is_silent(self, api, bot, mocker):
        """Nobody is waiting on it, so it must not surface as an error."""
        mocker.patch.object(
            bot, "download_file", side_effect=RuntimeError("boom")
        )

        with pytest.raises(RuntimeError):
            await read(api, 0, 10)
        await asyncio.sleep(0.05)
