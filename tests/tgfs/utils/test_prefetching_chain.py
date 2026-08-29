import asyncio
from typing import AsyncIterator, List, Optional

import pytest

from tgfs.utils.prefetching_chain import prefetching_chain


class RecordingSource:
    """An async iterable that reports when it is read and when it is closed."""

    def __init__(self, chunks: List[bytes], error: Optional[Exception] = None):
        self._chunks = list(chunks)
        self._error = error
        self.started = False
        self.closed = False
        self.delivered: List[bytes] = []

    async def __aiter__(self) -> AsyncIterator[bytes]:  # pragma: no cover - unused
        raise NotImplementedError

    def __call__(self) -> AsyncIterator[bytes]:
        return self._gen()

    async def _gen(self) -> AsyncIterator[bytes]:
        self.started = True
        try:
            for chunk in self._chunks:
                await asyncio.sleep(0)
                self.delivered.append(chunk)
                yield chunk
            if self._error:
                raise self._error
        finally:
            self.closed = True


def _source(chunks: List[bytes], error: Optional[Exception] = None):
    recorder = RecordingSource(chunks, error)
    return recorder, recorder()


async def _drain(iterator) -> List[bytes]:
    return [chunk async for chunk in iterator]


class TestOrdering:
    @pytest.mark.asyncio
    async def test_output_is_the_concatenation_in_order(self):
        _, a = _source([b"a1", b"a2"])
        _, b = _source([b"b1"])
        _, c = _source([b"c1", b"c2"])

        assert await _drain(prefetching_chain([a, b, c])) == [
            b"a1",
            b"a2",
            b"b1",
            b"c1",
            b"c2",
        ]

    @pytest.mark.asyncio
    async def test_no_sources(self):
        assert await _drain(prefetching_chain([])) == []

    @pytest.mark.asyncio
    async def test_empty_sources_are_skipped(self):
        _, a = _source([b"a"])
        _, empty = _source([])
        _, b = _source([b"b"])

        assert await _drain(prefetching_chain([a, empty, b])) == [b"a", b"b"]

    @pytest.mark.asyncio
    async def test_empty_chunks_are_passed_through(self):
        """``b""`` is data as far as the caller is concerned, not an end marker."""
        _, a = _source([b"", b"x"])

        assert await _drain(prefetching_chain([a])) == [b"", b"x"]


class TestPrefetching:
    @pytest.mark.asyncio
    async def test_later_sources_run_before_the_caller_reaches_them(self):
        """The point of the whole thing: segments are read concurrently."""
        first, a = _source([b"a1", b"a2"])
        second, b = _source([b"b1", b"b2"])

        chain = prefetching_chain([a, b], concurrency=2)
        await chain.__anext__()  # only the very first chunk
        await asyncio.sleep(0.05)

        assert second.started
        assert second.delivered  # already fetched, without being asked yet

        await chain.aclose()

    @pytest.mark.asyncio
    async def test_reading_ahead_is_bounded_by_the_queue(self):
        """A stalled consumer must stop the producers, not buffer the file."""
        source, a = _source([bytes([i]) for i in range(50)])

        chain = prefetching_chain([a], concurrency=1, queue_depth=2)
        await chain.__anext__()
        await asyncio.sleep(0.05)

        # One chunk handed out, a bounded few buffered -- not all fifty.
        assert len(source.delivered) <= 5

        await chain.aclose()

    @pytest.mark.asyncio
    async def test_concurrency_limits_how_many_sources_run_at_once(self):
        recorders = []
        sources = []
        for i in range(4):
            recorder, gen = _source([bytes([i])])
            recorders.append(recorder)
            sources.append(gen)

        chain = prefetching_chain(sources, concurrency=2)
        await chain.__anext__()
        await asyncio.sleep(0.05)

        assert not recorders[3].started

        await chain.aclose()


class TestFailures:
    @pytest.mark.asyncio
    async def test_an_error_surfaces_after_the_bytes_before_it(self):
        _, a = _source([b"a1"])
        _, b = _source([b"b1"], error=RuntimeError("boom"))

        chain = prefetching_chain([a, b])
        seen = []
        with pytest.raises(RuntimeError, match="boom"):
            async for chunk in chain:
                seen.append(chunk)

        assert seen == [b"a1", b"b1"]

    @pytest.mark.asyncio
    async def test_a_failure_does_not_pre_empt_earlier_bytes(self):
        """A later segment blowing up early must not jump the queue."""
        _, a = _source([b"a1", b"a2", b"a3"])
        _, b = _source([], error=RuntimeError("boom"))

        seen = []
        with pytest.raises(RuntimeError, match="boom"):
            async for chunk in prefetching_chain([a, b], concurrency=2):
                seen.append(chunk)

        assert seen == [b"a1", b"a2", b"a3"]


class TestCleanup:
    @pytest.mark.asyncio
    async def test_abandoning_the_stream_closes_running_sources(self):
        first, a = _source([bytes([i]) for i in range(50)])
        second, b = _source([bytes([i]) for i in range(50)])

        chain = prefetching_chain([a, b], concurrency=2)
        await chain.__anext__()
        await chain.aclose()
        await asyncio.sleep(0)

        assert first.closed
        assert second.closed

    @pytest.mark.asyncio
    async def test_sources_never_started_are_finalized(self):
        """Sources past the window are closed without ever being read.

        Their bodies never ran, so there is nothing to unwind -- but they
        still have to be finalized, or an abandoned download leaves
        un-awaited generators behind.
        """
        _, a = _source([b"a"])
        never, b = _source([b"b"])

        chain = prefetching_chain([a, b], concurrency=1)
        await chain.__anext__()
        await chain.aclose()

        assert not never.started
        with pytest.raises(StopAsyncIteration):
            await b.__anext__()

    @pytest.mark.asyncio
    async def test_no_tasks_are_left_behind(self):
        before = len(asyncio.all_tasks())
        _, a = _source([bytes([i]) for i in range(20)])
        _, b = _source([bytes([i]) for i in range(20)])

        chain = prefetching_chain([a, b], concurrency=2)
        await chain.__anext__()
        await chain.aclose()
        await asyncio.sleep(0)

        assert len(asyncio.all_tasks()) == before
