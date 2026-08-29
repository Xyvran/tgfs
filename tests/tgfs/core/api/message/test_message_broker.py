import asyncio
from typing import List, Optional, Sequence, cast
from unittest.mock import Mock

import pytest

from tgfs.core.api.message import message_broker as mb
from tgfs.core.api.message.message_broker import MessageBroker
from tgfs.reqres import GetMessagesResp, MessageResp
from tgfs.telegram.interface import ITDLibClient, TDLibApi
from tgfs.utils.message_cache import channel_cache, global_message_cache


def _message(message_id: int) -> MessageResp:
    return MessageResp(message_id=message_id, text="", document=None)


def _ids(messages: Sequence[Optional[MessageResp]]) -> List[int]:
    assert all(m is not None for m in messages)
    return [m.message_id for m in messages if m is not None]


class FakeBot:
    """Records every batch it is asked for, so coalescing stays observable.

    Fills the channel cache on the way out, the way the real Telegram
    implementations do -- that is what lets the broker's cache
    short-circuit be exercised.
    """

    def __init__(self, name: str = "bot", fail: Optional[Exception] = None):
        self.name = name
        self.fail = fail
        self.batches: List[tuple] = []

    async def get_messages(self, req) -> GetMessagesResp:
        self.batches.append(tuple(sorted(req.message_ids)))
        if self.fail:
            raise self.fail
        messages = [_message(mid) for mid in req.message_ids]
        cache = channel_cache(req.chat).id
        for message in messages:
            cache[message.message_id] = message
        return GetMessagesResp(messages)

    async def get_me(self):
        return Mock(name_=self.name, name=self.name)


@pytest.fixture(autouse=True)
def fast_delay(mocker):
    mocker.patch.object(mb, "DELAY", 0.02)


@pytest.fixture(autouse=True)
def clean_cache():
    global_message_cache.clear()
    yield
    global_message_cache.clear()


def _broker(*bots: FakeBot, channel: int = 4242) -> MessageBroker:
    return MessageBroker(
        TDLibApi(bots=cast(List[ITDLibClient], list(bots))), channel
    )


class TestBatching:
    @pytest.mark.asyncio
    async def test_requests_in_one_window_share_a_single_call(self):
        bot = FakeBot()
        broker = _broker(bot)

        results = await asyncio.gather(
            broker.get_messages([1, 2]), broker.get_messages([2, 3])
        )

        assert len(bot.batches) == 1
        assert bot.batches[0] == (1, 2, 3)
        assert _ids(results[0]) == [1, 2]
        assert _ids(results[1]) == [2, 3]

    @pytest.mark.asyncio
    async def test_a_steady_request_stream_does_not_postpone_the_flush(self):
        """The window runs from the first pending request, not the last.

        Restarting the timer on every arrival is what used to let a busy
        client starve the request that had been waiting longest.
        """
        bot = FakeBot()
        broker = _broker(bot)

        first = asyncio.ensure_future(broker.get_messages([1]))
        noise: List[asyncio.Future] = []

        async def keep_asking() -> None:
            for message_id in range(2, 20):
                await asyncio.sleep(mb.DELAY / 4)
                noise.append(asyncio.ensure_future(broker.get_messages([message_id])))

        asking = asyncio.ensure_future(keep_asking())
        try:
            result = await asyncio.wait_for(first, timeout=mb.DELAY * 10)
        finally:
            asking.cancel()
            await asyncio.gather(asking, *noise, return_exceptions=True)

        assert _ids(result) == [1]

    @pytest.mark.asyncio
    async def test_a_later_request_starts_a_new_window(self):
        bot = FakeBot()
        broker = _broker(bot)

        await broker.get_messages([1])
        await broker.get_messages([2])

        assert bot.batches == [(1,), (2,)]

    @pytest.mark.asyncio
    async def test_cached_messages_skip_the_broker(self):
        bot = FakeBot()
        broker = _broker(bot)

        await broker.get_messages([1])
        await broker.get_messages([1])

        assert len(bot.batches) == 1


class TestFailover:
    @pytest.mark.asyncio
    async def test_a_failing_bot_is_retried_on_the_next_one(self):
        failing = FakeBot("failing", fail=RuntimeError("boom"))
        healthy = FakeBot("healthy")
        broker = _broker(failing, healthy)

        result = await broker.get_messages([7])

        assert _ids(result) == [7]
        assert healthy.batches == [(7,)]

    @pytest.mark.asyncio
    async def test_a_single_bot_deployment_still_attempts_the_request(self):
        """A lone bot must be tried once.

        The retry width used to come from ``bot.tokens`` in the config,
        which is empty for deployments still on the legacy ``bot.token``
        key -- the loop then never ran and every request failed silently.
        """
        only = FakeBot("only")
        broker = _broker(only)

        result = await broker.get_messages([9])

        assert _ids(result) == [9]
        assert only.batches == [(9,)]

    @pytest.mark.asyncio
    async def test_all_bots_failing_propagates_to_the_caller(self):
        broker = _broker(
            FakeBot("a", fail=RuntimeError("boom")),
            FakeBot("b", fail=RuntimeError("boom")),
        )

        with pytest.raises(RuntimeError, match="boom"):
            await broker.get_messages([1])
