import datetime
import json
import logging
import os
import queue
import tempfile
import threading
from typing import Iterable, Optional, Tuple

from github.Repository import Repository

logger = logging.getLogger(__name__)

CACHE_VERSION = 1

# ``compare`` returns at most 300 entries in its file list, so a larger diff
# cannot be mapped back to the directories it touched and the whole cache has
# to be rebuilt rather than silently kept stale.
COMPARE_FILE_LIMIT = 300

# Two workers keep the fill-in gentle enough that GitHub does not start
# throttling the burst, which is what turned the old eager version into
# minutes of backoff sleeps.
WORKER_COUNT = 2

# Write the cache out every so many resolutions so a restart mid-warmup keeps
# what was already paid for.
SAVE_EVERY = 25

Timestamps = Tuple[datetime.datetime, datetime.datetime]


def _to_iso(value: datetime.datetime) -> str:
    return value.isoformat()


def _from_iso(value: object) -> Optional[datetime.datetime]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError:
        return None


def _ancestor_dirs(path: str) -> Iterable[str]:
    """Every directory path containing ``path``, excluding the repo root.

    ``Filme/Heat (1995)/movie.42`` yields ``Filme`` and ``Filme/Heat (1995)``:
    a commit touching that blob changes the modified date of both.
    """
    parts = path.split("/")[:-1]
    for i in range(1, len(parts) + 1):
        yield "/".join(parts[:i])


def cache_file_name(repo: str, branch: str) -> str:
    """A file name per (repo, branch) that is safe on every filesystem."""
    slug = "".join(c if c.isalnum() or c in "-_." else "-" for c in f"{repo}-{branch}")
    return f"dir-timestamps-{slug}.json"


class DirTimestampStore:
    """Persistent created/modified dates for the metadata repo's directories.

    Reading a directory's real dates costs two ``get_commits`` calls, ~0.6s
    each, and the tree holds hundreds of directories -- doing that eagerly on
    every start cost minutes of boot and ~900 of the 5000 hourly GitHub calls,
    growing with every new folder. The dates only move when a commit touches
    the directory, so they are cached on disk and revalidated against the repo
    head with a single ``compare`` call: entries under a changed path are
    dropped, everything else survives the restart untouched.

    Lookups never block. A miss returns ``None`` and queues the path for the
    background workers, so a cold cache costs a folder its real dates for a
    few seconds instead of costing the whole server its startup.
    """

    def __init__(self, repo: Repository, branch: str, path: str) -> None:
        self._repo = repo
        self._branch = branch
        self._path = path

        self._lock = threading.Lock()
        self._entries: dict[str, Timestamps] = {}
        self._head: Optional[str] = None
        self._queued: set[str] = set()
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._workers: list[threading.Thread] = []
        self._unsaved = 0

    # --- loading and revalidation -------------------------------------------

    def load(self) -> None:
        """Read the cache and drop whatever the repo has changed since.

        Best-effort throughout: a missing, unreadable or stale cache only
        means the dates get filled in again in the background.
        """
        cached_head, entries = self._read_file()
        head = self._current_head()

        if cached_head and head and cached_head != head:
            entries = self._drop_changed(entries, cached_head, head)
        elif not cached_head:
            # No head to compare against -- the entries could describe any
            # state of the repo, so none of them can be trusted.
            entries = {}

        with self._lock:
            self._entries = entries
            self._head = head or cached_head
        logger.info(
            f"Directory timestamp cache: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} "
            f"for {self._repo.full_name}@{self._branch}"
        )

    def _current_head(self) -> Optional[str]:
        try:
            return self._repo.get_branch(self._branch).commit.sha
        except Exception as ex:
            logger.debug(f"Could not read the head of {self._branch}: {ex}")
            return None

    def _read_file(self) -> Tuple[Optional[str], dict[str, Timestamps]]:
        try:
            with open(self._path, encoding="utf-8") as fp:
                data = json.load(fp)
        except FileNotFoundError:
            return None, {}
        except Exception as ex:
            logger.warning(f"Ignoring unreadable timestamp cache {self._path}: {ex}")
            return None, {}

        if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
            return None, {}
        if data.get("repo") != self._repo.full_name or data.get("branch") != self._branch:
            return None, {}

        entries: dict[str, Timestamps] = {}
        for path, value in (data.get("paths") or {}).items():
            if not isinstance(value, dict):
                continue
            created = _from_iso(value.get("created"))
            modified = _from_iso(value.get("modified"))
            if created is not None and modified is not None:
                entries[path] = (created, modified)
        return data.get("head"), entries

    def _drop_changed(
        self, entries: dict[str, Timestamps], base: str, head: str
    ) -> dict[str, Timestamps]:
        try:
            comparison = self._repo.compare(base, head)
            files = list(comparison.files)
        except Exception as ex:
            logger.info(f"Cannot diff {base[:8]}..{head[:8]}, rebuilding the cache: {ex}")
            return {}

        if len(files) >= COMPARE_FILE_LIMIT:
            logger.info(
                f"{len(files)} changed files since {base[:8]} exceeds the compare "
                "limit, rebuilding the cache"
            )
            return {}

        stale: set[str] = set()
        for changed in files:
            for name in (changed.filename, getattr(changed, "previous_filename", None)):
                if name:
                    stale.update(_ancestor_dirs(name))

        kept = {path: ts for path, ts in entries.items() if path not in stale}
        logger.info(
            f"{len(files)} file(s) changed since {base[:8]}: dropped "
            f"{len(entries) - len(kept)} of {len(entries)} cached directories"
        )
        return kept

    # --- lookups ------------------------------------------------------------

    def get(self, path: str) -> Optional[Timestamps]:
        """Cached dates for ``path``, or ``None`` after queueing a lookup."""
        with self._lock:
            found = self._entries.get(path)
            if found is not None:
                return found
        self.request(path)
        return None

    def request(self, path: str) -> None:
        """Queue ``path`` for the background workers. Cheap and idempotent."""
        if not path:
            return
        with self._lock:
            if path in self._entries or path in self._queued:
                return
            self._queued.add(path)
        self._queue.put(path)
        self._ensure_workers()

    # --- background fill ----------------------------------------------------

    def _ensure_workers(self) -> None:
        with self._lock:
            if self._workers:
                return
            self._workers = [
                threading.Thread(
                    target=self._work,
                    name=f"dir-timestamps-{i}",
                    daemon=True,
                )
                for i in range(WORKER_COUNT)
            ]
            workers = list(self._workers)
        for worker in workers:
            worker.start()

    def _work(self) -> None:
        while True:
            path = self._queue.get()
            try:
                self._resolve(path)
            except Exception as ex:  # a worker must never die on one path
                logger.debug(f"Timestamp lookup for {path} failed: {ex}")
            finally:
                with self._lock:
                    self._queued.discard(path)
                self._queue.task_done()
            if self._queue.empty():
                self.save()

    def _resolve(self, path: str) -> None:
        # The ``.gitkeep`` placeholder is written exactly once, when the
        # directory is created, and never touched again, so the commit that
        # introduced it is the true creation date. ``modified`` is the newest
        # commit anywhere under the directory path.
        modified = self._latest_commit_date(path)
        created = self._latest_commit_date(f"{path}/.gitkeep") or modified
        if created is None or modified is None:
            return

        with self._lock:
            self._entries[path] = (created, modified)
            self._unsaved += 1
            due = self._unsaved >= SAVE_EVERY
        if due:
            self.save()

    def _latest_commit_date(self, path: str) -> Optional[datetime.datetime]:
        try:
            commits = self._repo.get_commits(sha=self._branch, path=path)
            return commits[0].commit.committer.date
        except Exception as ex:
            # Best-effort enrichment only: missing history, an API error or any
            # unexpected response must never propagate.
            logger.debug(f"No commit history for {path}: {ex}")
            return None

    # --- persistence --------------------------------------------------------

    def save(self) -> None:
        with self._lock:
            if not self._unsaved:
                return
            payload = {
                "version": CACHE_VERSION,
                "repo": self._repo.full_name,
                "branch": self._branch,
                "head": self._head,
                "paths": {
                    path: {"created": _to_iso(created), "modified": _to_iso(modified)}
                    for path, (created, modified) in self._entries.items()
                },
            }
            self._unsaved = 0

        try:
            directory = os.path.dirname(self._path) or "."
            os.makedirs(directory, exist_ok=True)
            # Write beside the target and rename, so a crash mid-write leaves
            # the previous cache intact instead of a truncated file.
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".dir-timestamps-")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fp:
                    json.dump(payload, fp)
                os.replace(tmp, self._path)
            except Exception:
                os.unlink(tmp)
                raise
        except Exception as ex:
            logger.warning(f"Could not write the timestamp cache {self._path}: {ex}")
            with self._lock:
                self._unsaved += 1
