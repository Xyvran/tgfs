"""Measure what prefetching buys on a simulated Telegram link.

There is no Telegram access in CI, and a real measurement needs a real
channel -- but the thing that changed is structural, not bandwidth-bound:
segments used to be fetched one after another even though they were meant
to run in parallel. That is visible against a fake client with nothing but
an artificial per-chunk latency.

Run with:  poetry run python scripts/measure_transfer.py
"""

# A measurement CLI; its results are meant for a terminal.
# ruff: noqa: T201

import argparse
import asyncio
import time
from typing import AsyncIterator, List

from tgfs.utils.prefetching_chain import prefetching_chain

CHUNK = b"x" * 1024


def make_source(chunks: int, latency: float) -> AsyncIterator[bytes]:
    """A stand-in for one download segment: every chunk costs a round trip."""

    async def gen() -> AsyncIterator[bytes]:
        for _ in range(chunks):
            await asyncio.sleep(latency)
            yield CHUNK

    return gen()


async def drain_sequentially(sources: List[AsyncIterator[bytes]]) -> int:
    """What chaining the segments used to do: one after another."""
    total = 0
    for source in sources:
        async for chunk in source:
            total += len(chunk)
    return total


async def drain_prefetched(
    sources: List[AsyncIterator[bytes]], concurrency: int, depth: int
) -> int:
    total = 0
    async for chunk in prefetching_chain(
        sources, concurrency=concurrency, queue_depth=depth
    ):
        total += len(chunk)
    return total


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--segments", type=int, default=4, help="pieces fetched at once"
    )
    parser.add_argument("--chunks", type=int, default=4, help="chunks per piece")
    parser.add_argument("--latency", type=float, default=0.05, help="seconds per chunk")
    parser.add_argument(
        "--depth",
        type=int,
        default=0,
        help="queue depth per piece; 0 means a whole piece fits (production default)",
    )
    args = parser.parse_args()
    depth = args.depth or args.chunks

    def fresh() -> List[AsyncIterator[bytes]]:
        return [make_source(args.chunks, args.latency) for _ in range(args.segments)]

    started = time.perf_counter()
    size = await drain_sequentially(fresh())
    sequential = time.perf_counter() - started

    started = time.perf_counter()
    await drain_prefetched(fresh(), args.segments, depth)
    prefetched = time.perf_counter() - started

    mib = size / (1024 * 1024)
    print(
        f"{args.segments} pieces x {args.chunks} chunks, "
        f"{args.latency * 1000:.0f} ms per chunk, queue depth {depth} "
        f"({mib:.2f} MiB total)"
    )
    print(f"  sequential : {sequential:6.2f}s  ({mib / sequential:6.2f} MiB/s)")
    print(f"  prefetched : {prefetched:6.2f}s  ({mib / prefetched:6.2f} MiB/s)")
    print(f"  speedup    : {sequential / prefetched:6.2f}x")


if __name__ == "__main__":
    asyncio.run(main())
