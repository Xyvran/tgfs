import logging
from collections import OrderedDict
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# (channel id, message id, block index)
BlockKey = Tuple[int, int, int]


class ChunkCache:
    """A byte-budgeted LRU over fixed-size blocks of message content.

    Reads repeat far more than they look like they do: a video player
    re-requests the bytes around a seek, an SFTP client walks a file in
    kilobyte-sized reads, and every one of those used to be its own trip to
    Telegram. Caching whole blocks turns a run of small reads into one
    fetch, and a backward seek into no fetch at all.

    The budget is counted in bytes rather than entries because that is the
    quantity that actually has to be bounded -- an entry count says nothing
    about how much memory a cache of megabyte blocks is holding.

    Blocks are stored only when complete, so a short read can never be
    served as though it were the whole block.
    """

    def __init__(self, budget_bytes: int):
        self._budget = max(0, budget_bytes)
        self._blocks: "OrderedDict[BlockKey, bytes]" = OrderedDict()
        self._size = 0
        self.hits = 0
        self.misses = 0

    @property
    def enabled(self) -> bool:
        return self._budget > 0

    @property
    def size(self) -> int:
        return self._size

    def get(self, key: BlockKey) -> Optional[bytes]:
        if not self.enabled:
            return None
        if (block := self._blocks.get(key)) is None:
            self.misses += 1
            return None
        self._blocks.move_to_end(key)
        self.hits += 1
        return block

    def contains(self, key: BlockKey) -> bool:
        """Whether a block is held, without counting it as a hit or miss.

        Read-ahead asks about blocks nobody requested, so its lookups must
        not show up in the hit rate.
        """
        return self.enabled and key in self._blocks

    def put(self, key: BlockKey, block: bytes) -> None:
        if not self.enabled or not block:
            return
        # A single block larger than the whole budget would evict everything
        # and still not fit; keeping it out is cheaper than thrashing.
        if len(block) > self._budget:
            return

        if key in self._blocks:
            self._size -= len(self._blocks.pop(key))

        self._blocks[key] = block
        self._size += len(block)

        while self._size > self._budget:
            _, evicted = self._blocks.popitem(last=False)
            self._size -= len(evicted)

    def invalidate(self, channel: int, message_id: int) -> None:
        """Drop every block of one message.

        Editing a message replaces its document, so anything cached for it
        describes bytes that are no longer there.
        """
        if not self.enabled:
            return
        stale = [
            key
            for key in self._blocks
            if key[0] == channel and key[1] == message_id
        ]
        for key in stale:
            self._size -= len(self._blocks.pop(key))

    def clear(self) -> None:
        self._blocks.clear()
        self._size = 0
        self.hits = 0
        self.misses = 0


__cache: Optional[ChunkCache] = None


def chunk_cache() -> ChunkCache:
    """The process-wide block cache, sized from the config on first use."""
    global __cache
    if __cache is None:
        from tgfs.config import get_config

        budget = get_config().tgfs.transfer.chunk_cache_bytes
        __cache = ChunkCache(budget)
        if __cache.enabled:
            logger.info(f"Chunk cache enabled with a budget of {budget} bytes")
    return __cache


def reset_chunk_cache() -> None:
    """Drop the cache and its configuration; the next use rebuilds it."""
    global __cache
    __cache = None


def block_range(begin: int, end: int, block_size: int) -> range:
    """Indices of the blocks covering the inclusive range ``[begin, end]``."""
    return range(begin // block_size, end // block_size + 1)


def block_bounds(index: int, block_size: int, total_size: int) -> Tuple[int, int]:
    """Inclusive byte bounds of one block, clipped to the document."""
    begin = index * block_size
    return begin, min(begin + block_size, total_size) - 1


def block_length(index: int, block_size: int, total_size: int) -> int:
    """How long a complete block at ``index`` is -- the last one is short."""
    begin, end = block_bounds(index, block_size, total_size)
    return max(0, end - begin + 1)

