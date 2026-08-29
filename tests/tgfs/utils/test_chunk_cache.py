import pytest

from tgfs.utils.chunk_cache import (
    ChunkCache,
    block_bounds,
    block_length,
    block_range,
    chunk_cache,
    reset_chunk_cache,
)

KIB = 1024


class TestBudget:
    def test_a_zero_budget_disables_the_cache(self):
        cache = ChunkCache(0)

        cache.put((1, 2, 0), b"x" * 100)

        assert not cache.enabled
        assert cache.get((1, 2, 0)) is None
        assert cache.size == 0

    def test_stored_blocks_come_back(self):
        cache = ChunkCache(10 * KIB)

        cache.put((1, 2, 0), b"a" * KIB)

        assert cache.get((1, 2, 0)) == b"a" * KIB
        assert cache.size == KIB

    def test_the_budget_is_counted_in_bytes(self):
        cache = ChunkCache(3 * KIB)

        for index in range(3):
            cache.put((1, 2, index), b"x" * KIB)
        assert cache.size == 3 * KIB

        cache.put((1, 2, 3), b"x" * KIB)

        assert cache.size == 3 * KIB
        assert cache.get((1, 2, 0)) is None  # the oldest one made room

    def test_eviction_follows_use_not_insertion(self):
        cache = ChunkCache(3 * KIB)
        for index in range(3):
            cache.put((1, 2, index), b"x" * KIB)

        cache.get((1, 2, 0))  # freshly used, so no longer the eviction target
        cache.put((1, 2, 3), b"x" * KIB)

        assert cache.get((1, 2, 0)) is not None
        assert cache.get((1, 2, 1)) is None

    def test_a_block_larger_than_the_budget_is_not_stored(self):
        """Storing it would evict everything and still not fit."""
        cache = ChunkCache(KIB)

        cache.put((1, 2, 0), b"x" * (2 * KIB))

        assert cache.get((1, 2, 0)) is None
        assert cache.size == 0

    def test_replacing_a_block_does_not_double_count_it(self):
        cache = ChunkCache(10 * KIB)

        cache.put((1, 2, 0), b"a" * KIB)
        cache.put((1, 2, 0), b"b" * KIB)

        assert cache.size == KIB
        assert cache.get((1, 2, 0)) == b"b" * KIB


class TestInvalidation:
    def test_only_the_named_message_is_dropped(self):
        cache = ChunkCache(10 * KIB)
        cache.put((1, 2, 0), b"a" * KIB)
        cache.put((1, 2, 1), b"a" * KIB)
        cache.put((1, 3, 0), b"b" * KIB)
        cache.put((9, 2, 0), b"c" * KIB)

        cache.invalidate(1, 2)

        assert cache.get((1, 2, 0)) is None
        assert cache.get((1, 2, 1)) is None
        assert cache.get((1, 3, 0)) is not None
        assert cache.get((9, 2, 0)) is not None
        assert cache.size == 2 * KIB


class TestStatistics:
    def test_hits_and_misses_are_counted(self):
        cache = ChunkCache(10 * KIB)
        cache.put((1, 2, 0), b"a")

        cache.get((1, 2, 0))
        cache.get((1, 2, 1))

        assert (cache.hits, cache.misses) == (1, 1)

    def test_contains_does_not_count(self):
        """Read-ahead asks about blocks nobody requested."""
        cache = ChunkCache(10 * KIB)
        cache.put((1, 2, 0), b"a")

        assert cache.contains((1, 2, 0))
        assert not cache.contains((1, 2, 1))
        assert (cache.hits, cache.misses) == (0, 0)


class TestBlockMath:
    def test_block_range_covers_both_ends(self):
        assert list(block_range(0, 99, 100)) == [0]
        assert list(block_range(0, 100, 100)) == [0, 1]
        assert list(block_range(150, 250, 100)) == [1, 2]

    def test_block_bounds_are_inclusive_and_clipped(self):
        assert block_bounds(0, 100, 250) == (0, 99)
        assert block_bounds(2, 100, 250) == (200, 249)

    def test_the_last_block_is_short(self):
        assert block_length(0, 100, 250) == 100
        assert block_length(2, 100, 250) == 50


class TestGlobalCache:
    def test_the_budget_comes_from_the_config(self, mocker):
        reset_chunk_cache()
        try:
            cfg = mocker.Mock()
            cfg.tgfs.transfer.chunk_cache_bytes = 4 * KIB
            mocker.patch("tgfs.config.get_config", return_value=cfg)

            assert chunk_cache().enabled
            assert chunk_cache() is chunk_cache()
        finally:
            reset_chunk_cache()

    def test_it_is_disabled_by_default(self):
        reset_chunk_cache()
        try:
            assert not chunk_cache().enabled
        finally:
            reset_chunk_cache()
