import asyncio
from dataclasses import dataclass
from typing import AsyncGenerator, AsyncIterable, Dict, Iterable, List, Optional

# How many sources are read at once, and how many chunks may wait in front of
# each of them. Peak memory of one stream is roughly
# ``concurrency * queue_depth * chunk_size``, so both stay small by default.
DEFAULT_CONCURRENCY = 4
DEFAULT_QUEUE_DEPTH = 2


@dataclass
class _End:
    """Marks a source as finished, carrying whatever ended it."""

    error: Optional[BaseException] = None


@dataclass
class _Segment:
    queue: "asyncio.Queue"
    task: "asyncio.Task"


async def _pump(source: AsyncIterable[bytes], queue: "asyncio.Queue") -> None:
    """Drain one source into its queue, ending with an ``_End`` marker.

    Errors travel through the queue rather than out of the task, so they
    surface at the position where the source's bytes belong -- a failure in
    a later segment must not pre-empt bytes the caller is still owed from
    an earlier one.
    """
    error: Optional[BaseException] = None
    try:
        async for chunk in source:
            await queue.put(chunk)
    except Exception as ex:
        error = ex
    await queue.put(_End(error))


async def prefetching_chain(
    sources: Iterable[AsyncIterable[bytes]],
    concurrency: int = DEFAULT_CONCURRENCY,
    queue_depth: int = DEFAULT_QUEUE_DEPTH,
) -> AsyncGenerator[bytes, None]:
    """Concatenate byte streams, reading several of them ahead of the caller.

    The output is exactly the concatenation of ``sources`` in order -- byte
    ranges depend on it -- but the sources are read concurrently instead of
    one after the other, and every source runs a little ahead of the
    consumer. That is what makes a split download actually parallel: simply
    chaining the segments would issue the second request only once the first
    one had been drained.

    Reading ahead is bounded by a queue per source, so a consumer that
    stalls (a paused video, a slow SFTP client) stops the producers instead
    of buffering a whole file.

    This is an async generator on purpose: abandoned downloads are the norm,
    and a generator is finalized -- running the cleanup below -- when the
    caller stops iterating or drops it, whereas a plain iterator class would
    leave its background tasks running.
    """
    ordered: List[AsyncIterable[bytes]] = list(sources)
    concurrency = max(1, concurrency)
    queue_depth = max(1, queue_depth)

    segments: Dict[int, _Segment] = {}
    started = 0
    current = 0

    def start_window() -> None:
        """Keep the next ``concurrency`` sources running."""
        nonlocal started
        limit = min(len(ordered), current + concurrency)
        while started < limit:
            queue: asyncio.Queue = asyncio.Queue(maxsize=queue_depth)
            segments[started] = _Segment(
                queue=queue,
                task=asyncio.create_task(_pump(ordered[started], queue)),
            )
            started += 1

    try:
        while current < len(ordered):
            start_window()
            item = await segments[current].queue.get()

            if isinstance(item, _End):
                del segments[current]
                current += 1
                if item.error is not None:
                    raise item.error
                continue

            yield item
    finally:
        for segment in segments.values():
            segment.task.cancel()
        if segments:
            await asyncio.gather(
                *(segment.task for segment in segments.values()),
                return_exceptions=True,
            )
        segments.clear()

        # Sources beyond the window were never iterated; closing them keeps
        # an abandoned download from leaving generators open.
        for source in ordered[started:]:
            if (aclose := getattr(source, "aclose", None)) is not None:
                await aclose()
