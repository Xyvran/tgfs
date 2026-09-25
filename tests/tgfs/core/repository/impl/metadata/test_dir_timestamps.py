import datetime
import json

import pytest
from unittest.mock import Mock, patch
from github.Repository import Repository

from tgfs.core.repository.impl.metadata.github_repo.dir_timestamps import (
    CACHE_VERSION,
    COMPARE_FILE_LIMIT,
    DirTimestampStore,
    _ancestor_dirs,
    cache_file_name,
)

CREATED = datetime.datetime(2024, 3, 1, 12, 0, tzinfo=datetime.timezone.utc)
MODIFIED = datetime.datetime(2025, 7, 4, 8, 30, tzinfo=datetime.timezone.utc)


@pytest.fixture(autouse=True)
def no_workers():
    """Keep the background fill off so every test stays deterministic.

    ``request`` still records what it queued; only the threads that would
    drain the queue are suppressed.
    """
    with patch.object(DirTimestampStore, "_ensure_workers"):
        yield


@pytest.fixture
def mock_repo():
    repo = Mock(spec=Repository)
    repo.full_name = "owner/test-repo"
    repo.get_branch.return_value.commit.sha = "head0000"
    return repo


def write_cache(path, paths, head="head0000", repo="owner/test-repo", branch="main"):
    path.write_text(
        json.dumps(
            {
                "version": CACHE_VERSION,
                "repo": repo,
                "branch": branch,
                "head": head,
                "paths": {
                    p: {"created": CREATED.isoformat(), "modified": MODIFIED.isoformat()}
                    for p in paths
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def changed_file(filename, previous_filename=None):
    changed = Mock()
    changed.filename = filename
    changed.previous_filename = previous_filename
    return changed


def store_for(mock_repo, path, branch="main"):
    return DirTimestampStore(repo=mock_repo, branch=branch, path=str(path))


class TestAncestorDirs:
    def test_yields_every_containing_directory(self):
        assert list(_ancestor_dirs("Filme/Heat (1995)/movie.42")) == [
            "Filme",
            "Filme/Heat (1995)",
        ]

    def test_file_at_the_root_has_no_ancestors(self):
        assert list(_ancestor_dirs("README.md")) == []


class TestCacheFileName:
    def test_slug_is_filesystem_safe(self):
        assert (
            cache_file_name("Xyvran/tgfs_repo", "master")
            == "dir-timestamps-Xyvran-tgfs_repo-master.json"
        )

    def test_repo_and_branch_get_separate_files(self):
        assert cache_file_name("a/b", "main") != cache_file_name("a/b", "dev")


class TestLoad:
    def test_unchanged_head_keeps_everything_without_a_diff(self, mock_repo, tmp_path):
        write_cache(tmp_path / "c.json", ["Filme", "Serien"])
        store = store_for(mock_repo, tmp_path / "c.json")

        store.load()

        assert store.get("Filme") == (CREATED, MODIFIED)
        assert store.get("Serien") == (CREATED, MODIFIED)
        mock_repo.compare.assert_not_called()

    def test_missing_file_is_not_an_error(self, mock_repo, tmp_path):
        store = store_for(mock_repo, tmp_path / "absent.json")

        store.load()

        assert store.get("Filme") is None

    def test_unreadable_file_is_ignored(self, mock_repo, tmp_path):
        cache = tmp_path / "c.json"
        cache.write_text("{ this is not json", encoding="utf-8")
        store = store_for(mock_repo, cache)

        store.load()

        assert store.get("Filme") is None

    def test_cache_without_a_head_is_dropped(self, mock_repo, tmp_path):
        # Without a head the entries could describe any state of the repo.
        write_cache(tmp_path / "c.json", ["Filme"], head=None)
        store = store_for(mock_repo, tmp_path / "c.json")

        store.load()

        assert store.get("Filme") is None

    def test_cache_of_another_repo_is_rejected(self, mock_repo, tmp_path):
        write_cache(tmp_path / "c.json", ["Filme"], repo="someone/else")
        store = store_for(mock_repo, tmp_path / "c.json")

        store.load()

        assert store.get("Filme") is None

    def test_cache_of_another_branch_is_rejected(self, mock_repo, tmp_path):
        write_cache(tmp_path / "c.json", ["Filme"], branch="dev")
        store = store_for(mock_repo, tmp_path / "c.json")

        store.load()

        assert store.get("Filme") is None

    def test_wrong_version_is_rejected(self, mock_repo, tmp_path):
        cache = tmp_path / "c.json"
        cache.write_text(
            json.dumps({"version": CACHE_VERSION + 1, "paths": {"Filme": {}}}),
            encoding="utf-8",
        )
        store = store_for(mock_repo, cache)

        store.load()

        assert store.get("Filme") is None

    def test_entries_with_unparsable_dates_are_skipped(self, mock_repo, tmp_path):
        cache = tmp_path / "c.json"
        cache.write_text(
            json.dumps(
                {
                    "version": CACHE_VERSION,
                    "repo": "owner/test-repo",
                    "branch": "main",
                    "head": "head0000",
                    "paths": {
                        "Filme": {"created": "not a date", "modified": "nope"},
                        "Serien": {
                            "created": CREATED.isoformat(),
                            "modified": MODIFIED.isoformat(),
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        store = store_for(mock_repo, cache)

        store.load()

        assert store.get("Filme") is None
        assert store.get("Serien") == (CREATED, MODIFIED)


class TestRevalidation:
    def test_only_the_directories_the_diff_touched_are_dropped(
        self, mock_repo, tmp_path
    ):
        write_cache(
            tmp_path / "c.json", ["Filme", "Filme/Heat (1995)", "Serien", "Serien/Dark"]
        )
        mock_repo.get_branch.return_value.commit.sha = "head1111"
        mock_repo.compare.return_value.files = [
            changed_file("Serien/Dark/episode.7")
        ]
        store = store_for(mock_repo, tmp_path / "c.json")

        store.load()

        # Ancestors of the changed blob lose their dates...
        assert store.get("Serien") is None
        assert store.get("Serien/Dark") is None
        # ...everything the commit did not touch survives the restart.
        assert store.get("Filme") == (CREATED, MODIFIED)
        assert store.get("Filme/Heat (1995)") == (CREATED, MODIFIED)
        mock_repo.compare.assert_called_once_with("head0000", "head1111")

    def test_a_rename_invalidates_both_sides(self, mock_repo, tmp_path):
        write_cache(tmp_path / "c.json", ["Filme", "Serien"])
        mock_repo.get_branch.return_value.commit.sha = "head1111"
        mock_repo.compare.return_value.files = [
            changed_file("Serien/movie.42", previous_filename="Filme/movie.42")
        ]
        store = store_for(mock_repo, tmp_path / "c.json")

        store.load()

        assert store.get("Filme") is None
        assert store.get("Serien") is None

    def test_a_diff_over_the_compare_limit_rebuilds(self, mock_repo, tmp_path):
        write_cache(tmp_path / "c.json", ["Filme"])
        mock_repo.get_branch.return_value.commit.sha = "head1111"
        # compare caps its file list, so a bigger diff cannot be mapped back
        # to the directories it touched.
        mock_repo.compare.return_value.files = [
            changed_file(f"Serien/ep.{i}") for i in range(COMPARE_FILE_LIMIT)
        ]
        store = store_for(mock_repo, tmp_path / "c.json")

        store.load()

        assert store.get("Filme") is None

    def test_a_failing_diff_rebuilds_rather_than_serving_stale_dates(
        self, mock_repo, tmp_path
    ):
        write_cache(tmp_path / "c.json", ["Filme"])
        mock_repo.get_branch.return_value.commit.sha = "head1111"
        mock_repo.compare.side_effect = Exception("no common ancestor")
        store = store_for(mock_repo, tmp_path / "c.json")

        store.load()

        assert store.get("Filme") is None

    def test_an_unreadable_head_keeps_the_cache(self, mock_repo, tmp_path):
        # The repo could not be asked, which is no reason to throw away dates
        # that were valid a moment ago.
        write_cache(tmp_path / "c.json", ["Filme"])
        mock_repo.get_branch.side_effect = Exception("offline")
        store = store_for(mock_repo, tmp_path / "c.json")

        store.load()

        assert store.get("Filme") == (CREATED, MODIFIED)
        mock_repo.compare.assert_not_called()


class TestLookups:
    def test_a_miss_queues_the_path_and_returns_nothing(self, mock_repo, tmp_path):
        store = store_for(mock_repo, tmp_path / "c.json")

        assert store.get("Filme") is None

        assert store._queue.get_nowait() == "Filme"

    def test_a_path_is_queued_only_once(self, mock_repo, tmp_path):
        store = store_for(mock_repo, tmp_path / "c.json")

        store.request("Filme")
        store.request("Filme")

        assert store._queue.qsize() == 1

    def test_a_hit_is_not_queued(self, mock_repo, tmp_path):
        write_cache(tmp_path / "c.json", ["Filme"])
        store = store_for(mock_repo, tmp_path / "c.json")
        store.load()

        assert store.get("Filme") == (CREATED, MODIFIED)
        assert store._queue.empty()

    def test_the_root_is_never_queued(self, mock_repo, tmp_path):
        store = store_for(mock_repo, tmp_path / "c.json")

        store.request("")

        assert store._queue.empty()


class TestResolve:
    def _commit_at(self, date):
        commit = Mock()
        commit.commit.committer.date = date
        return [commit]

    def test_created_comes_from_the_gitkeep_and_modified_from_the_directory(
        self, mock_repo, tmp_path
    ):
        # .gitkeep is written exactly once, when the directory is created, so
        # its commit is the true creation date.
        mock_repo.get_commits.side_effect = [
            self._commit_at(MODIFIED),  # anything under Filme
            self._commit_at(CREATED),  # Filme/.gitkeep
        ]
        store = store_for(mock_repo, tmp_path / "c.json")

        store._resolve("Filme")

        assert store.get("Filme") == (CREATED, MODIFIED)
        assert [c.kwargs["path"] for c in mock_repo.get_commits.call_args_list] == [
            "Filme",
            "Filme/.gitkeep",
        ]

    def test_a_missing_gitkeep_falls_back_to_the_directory_date(
        self, mock_repo, tmp_path
    ):
        mock_repo.get_commits.side_effect = [
            self._commit_at(MODIFIED),
            Exception("no history"),
        ]
        store = store_for(mock_repo, tmp_path / "c.json")

        store._resolve("Filme")

        assert store.get("Filme") == (MODIFIED, MODIFIED)

    def test_a_directory_without_history_is_not_stored(self, mock_repo, tmp_path):
        mock_repo.get_commits.side_effect = Exception("no history")
        store = store_for(mock_repo, tmp_path / "c.json")

        store._resolve("Filme")

        assert store._entries == {}


class TestPersistence:
    def test_save_then_load_returns_the_same_dates(self, mock_repo, tmp_path):
        cache = tmp_path / "sub" / "c.json"  # the directory does not exist yet
        commit = Mock()
        commit.commit.committer.date = CREATED
        mock_repo.get_commits.return_value = [commit]

        store = store_for(mock_repo, cache)
        store.load()
        store._resolve("Filme")
        store.save()

        reloaded = store_for(mock_repo, cache)
        reloaded.load()
        assert reloaded.get("Filme") == (CREATED, CREATED)

    def test_save_records_the_head_it_was_built_against(self, mock_repo, tmp_path):
        cache = tmp_path / "c.json"
        commit = Mock()
        commit.commit.committer.date = CREATED
        mock_repo.get_commits.return_value = [commit]

        store = store_for(mock_repo, cache)
        store.load()
        store._resolve("Filme")
        store.save()

        assert json.loads(cache.read_text(encoding="utf-8"))["head"] == "head0000"

    def test_save_without_changes_writes_nothing(self, mock_repo, tmp_path):
        cache = tmp_path / "c.json"
        store = store_for(mock_repo, cache)

        store.save()

        assert not cache.exists()

    def test_an_unwritable_path_keeps_the_dates_in_memory(self, mock_repo, tmp_path):
        commit = Mock()
        commit.commit.committer.date = CREATED
        mock_repo.get_commits.return_value = [commit]
        # A file where the cache expects a directory.
        blocker = tmp_path / "blocker"
        blocker.write_text("", encoding="utf-8")

        store = store_for(mock_repo, blocker / "c.json")
        store._resolve("Filme")
        store.save()

        assert store.get("Filme") == (CREATED, CREATED)
