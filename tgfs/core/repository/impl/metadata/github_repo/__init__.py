import asyncio
import datetime
import logging
from typing import Optional

from github import Github
from github.ContentFile import ContentFile
from github.GitTreeElement import GitTreeElement

from tgfs.config import GithubRepoConfig, expand_path
from tgfs.core.model import TGFSMetadata
from tgfs.core.repository.interface import IMetaDataRepository
from tgfs.crypto.path_names import (
    PathNameEncryptionError,
    decrypt_path_name,
    is_encrypted_path_name,
)

from .dir_timestamps import DirTimestampStore, cache_file_name
from .gh_directory import GithubConfig, GithubDirectory

logger = logging.getLogger(__name__)


class GithubRepoMetadataRepository(IMetaDataRepository):
    def __init__(
        self, config: GithubRepoConfig, name_key: Optional[bytes] = None
    ):
        super().__init__()

        gh = Github(config.access_token)
        repo = gh.get_repo(config.repo)

        self._timestamps = DirTimestampStore(
            repo=repo,
            branch=config.commit,
            path=expand_path(cache_file_name(config.repo, config.commit)),
        )

        self._ghc = GithubConfig(
            gh=gh,
            repo_name=config.repo,
            repo=repo,
            commit=config.commit,
            name_key=name_key,
            timestamps=self._timestamps,
        )

    async def push(self) -> None:
        pass

    async def get(self) -> TGFSMetadata:
        # One call to read the repo head plus at most one to diff it against
        # the cached one. Off the event loop because PyGithub is synchronous.
        await asyncio.to_thread(self._timestamps.load)
        root_dir = self._build_directory_structure()
        return TGFSMetadata(dir=root_dir)

    def _build_directory_structure(self) -> GithubDirectory:
        root = GithubDirectory(
            self._ghc, name="root", parent=None, children=[], files=[]
        )
        self._restore_root_timestamps(root)

        try:
            entries = self._read_tree()
            if entries is not None:
                self._build_from_tree(entries, root)
            else:
                contents = self._ghc.repo.get_contents("", ref=self._ghc.commit)
                self._process_contents(contents, root)
        except Exception as ex:
            logger.error(ex)

        return root

    def _read_tree(self) -> Optional[list[GitTreeElement]]:
        """The whole repo tree in one request, or ``None`` if it is unusable.

        ``get_contents`` lists exactly one directory, so walking the tree with
        it costs one round trip per directory -- 306 of them here, all before
        a single file can be listed. The recursive tree API returns every blob
        and subtree at once instead, which makes the load independent of how
        many folders the repo holds.

        GitHub truncates the response for very large trees. That would silently
        hide whole folders, so a truncated tree is refused and the caller walks
        the old way rather than serving an incomplete filesystem.
        """
        try:
            tree = self._ghc.repo.get_git_tree(self._ghc.commit, recursive=True)
            if tree.truncated:
                logger.warning(
                    f"Tree of {self._ghc.repo_name}@{self._ghc.commit} came back "
                    "truncated; falling back to a directory-by-directory walk"
                )
                return None
            return list(tree.tree)
        except Exception as ex:
            logger.warning(
                f"Could not read the tree of {self._ghc.repo_name}@{self._ghc.commit}, "
                f"falling back to a directory-by-directory walk: {ex}"
            )
            return None

    def _build_from_tree(
        self, entries: list[GitTreeElement], root: GithubDirectory
    ) -> None:
        """Materialise the in-memory tree from one flat list of tree entries.

        Entries carry full storage paths and arrive in no guaranteed order, so
        directories are resolved on demand and every missing parent is created
        along the way.
        """
        dirs: dict[str, GithubDirectory] = {"": root}

        for entry in entries:
            if entry.type == "tree":
                self._dir_at(entry.path, dirs)
            elif entry.type == "blob":
                parent_path, _, segment = entry.path.rpartition("/")
                if segment == ".gitkeep":
                    continue
                try:
                    stored_name, message_id = segment.rsplit(".", 1)
                    file_name, _ = self._decode_name(stored_name)
                    # attach, not create: the directory's date is the git
                    # history's, not the moment this tree was rebuilt.
                    self._dir_at(parent_path, dirs).attach_file_ref(
                        file_name, int(message_id)
                    )
                except ValueError:
                    logger.warning(
                        f"Invalid name format for {segment}, expected a format like 'name.message_id'"
                    )

    def _dir_at(
        self, storage_path: str, dirs: dict[str, GithubDirectory]
    ) -> GithubDirectory:
        """The directory at ``storage_path``, created with its parents if new."""
        found = dirs.get(storage_path)
        if found is not None:
            return found

        parent_path, _, segment = storage_path.rpartition("/")
        dir_name, was_encrypted = self._decode_name(segment)
        child = self._create_child_dir(
            dir_name,
            self._dir_at(parent_path, dirs),
            stored_encrypted=was_encrypted,
            defer_timestamps=True,
        )
        # Dates come from the cache on first read. Warming them here only
        # queues the path; the workers pay for the lookup in the background
        # instead of holding the load for two calls per directory.
        if self._ghc.timestamps is not None:
            self._ghc.timestamps.request(storage_path)
        dirs[storage_path] = child
        return child

    def _restore_root_timestamps(self, root: GithubDirectory) -> None:
        """Give the root its real dates from the repo's own metadata.

        The root has no ``.gitkeep`` to date it from, so fall back to the
        backing repository's creation and last-push timestamps instead of
        the ``now()`` dataclass default. Best-effort: any failure leaves the
        default rather than breaking the load.
        """
        try:
            created = self._ghc.repo.created_at
            modified = self._ghc.repo.pushed_at or self._ghc.repo.updated_at
            if isinstance(created, datetime.datetime):
                root.created_at = created
            if isinstance(modified, datetime.datetime):
                root.modified_at = modified
        except Exception as ex:
            logger.debug(f"Could not read repo timestamps for root: {ex}")

    def _create_child_dir(
        self,
        name: str,
        parent_dir: GithubDirectory,
        stored_encrypted: bool = False,
        defer_timestamps: bool = False,
    ) -> GithubDirectory:
        child_dir = GithubDirectory(
            self._ghc,
            name,
            parent_dir,
            stored_encrypted=stored_encrypted,
            defer_timestamps=defer_timestamps,
        )
        parent_dir.children.append(child_dir)
        return child_dir

    def _decode_name(self, raw: str) -> tuple[str, bool]:
        """Map an on-repo path segment to its (plaintext, was_encrypted) form.

        Legacy plaintext segments pass through unchanged; encrypted ones are
        decrypted with the configured key. This is what lets encrypted and
        plaintext entries coexist in the same repo during/after migration.
        """
        if not is_encrypted_path_name(raw):
            return raw, False
        key = self._ghc.name_key
        if key is None:
            return raw, True  # cannot decrypt without the key
        try:
            return decrypt_path_name(key, raw), True
        except PathNameEncryptionError as ex:
            logger.warning(f"Failed to decrypt path name {raw!r}: {ex}")
            return raw, True

    def _process_contents(
        self, contents: list[ContentFile] | ContentFile, parent_dir: GithubDirectory
    ) -> None:
        if not isinstance(contents, list):
            contents = [contents]

        for content in contents:
            if content.type == "dir":
                # content.name is the on-repo (possibly encrypted) segment;
                # decrypt it for the in-memory model but keep using
                # content.path (the storage path) for the git-history lookup.
                dir_name, was_encrypted = self._decode_name(content.name)
                child_dir = self._create_child_dir(
                    dir_name,
                    parent_dir,
                    stored_encrypted=was_encrypted,
                    defer_timestamps=True,
                )
                # Dates come from the cache on first read. Warming them here
                # only queues the path; the workers pay for the lookup in the
                # background instead of holding the boot for two calls each.
                if self._ghc.timestamps is not None:
                    self._ghc.timestamps.request(content.path)
                try:
                    child_contents = self._ghc.repo.get_contents(
                        content.path, ref=self._ghc.commit
                    )
                    self._process_contents(child_contents, child_dir)
                except Exception as ex:
                    logger.warning(
                        f"Failed to construct directory {content.name}: {ex}"
                    )
            elif content.type == "file":
                try:
                    if content.name == ".gitkeep":
                        continue
                    stored_name, message_id = content.name.rsplit(".", 1)
                    file_name, _ = self._decode_name(stored_name)
                    parent_dir.attach_file_ref(file_name, int(message_id))
                except ValueError:
                    logger.warning(
                        f"Invalid name format for {content.name}, expected a format like 'name.message_id'"
                    )
