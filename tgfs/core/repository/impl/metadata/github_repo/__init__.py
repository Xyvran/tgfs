import datetime
import logging
from typing import Optional

from github import Github
from github.ContentFile import ContentFile

from tgfs.config import GithubRepoConfig
from tgfs.core.model import TGFSDirectory, TGFSMetadata
from tgfs.core.repository.interface import IMetaDataRepository

from .gh_directory import GithubConfig, GithubDirectory

logger = logging.getLogger(__name__)


class GithubRepoMetadataRepository(IMetaDataRepository):
    def __init__(self, config: GithubRepoConfig):
        super().__init__()

        gh = Github(config.access_token)

        self._ghc = GithubConfig(
            gh=gh,
            repo_name=config.repo,
            repo=gh.get_repo(config.repo),
            commit=config.commit,
        )

    async def push(self) -> None:
        pass

    async def get(self) -> TGFSMetadata:
        root_dir = self._build_directory_structure()
        return TGFSMetadata(dir=root_dir)

    def _build_directory_structure(self) -> GithubDirectory:
        root = GithubDirectory(
            self._ghc, name="root", parent=None, children=[], files=[]
        )
        self._restore_root_timestamps(root)

        try:
            contents = self._ghc.repo.get_contents("", ref=self._ghc.commit)
            self._process_contents(contents, root)
        except Exception as ex:
            logger.error(ex)

        return root

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
        self, name: str, parent_dir: GithubDirectory
    ) -> GithubDirectory:
        child_dir = GithubDirectory(self._ghc, name, parent_dir)
        parent_dir.children.append(child_dir)
        return child_dir

    def _latest_commit_date(self, path: str) -> Optional[datetime.datetime]:
        """Date of the most recent commit touching ``path`` (newest first).

        Returns ``None`` when the path has no history, so callers can fall
        back gracefully instead of crashing the whole metadata load.
        """
        try:
            commits = self._ghc.repo.get_commits(sha=self._ghc.commit, path=path)
            return commits[0].commit.committer.date
        except Exception as ex:
            # Best-effort enrichment only: missing history, an API error, or any
            # unexpected response must never abort the directory load.
            logger.debug(f"No commit history for {path}: {ex}")
            return None

    def _restore_dir_timestamps(
        self, directory: GithubDirectory, dir_path: str
    ) -> None:
        """Recover a directory's real created/modified dates from git history.

        Without this the tree is rebuilt from the repo structure on every
        load and ``created_at``/``modified_at`` fall back to ``now()`` (the
        dataclass default), so WebDAV reports the server-start time for every
        folder. The ``.gitkeep`` placeholder is written exactly once when the
        directory is created and never touched again, so the commit that
        introduced it is the true creation date; ``modified_at`` is the newest
        commit anywhere under the directory path.
        """
        modified = self._latest_commit_date(dir_path)
        created = self._latest_commit_date(f"{dir_path}/.gitkeep")
        if created is None:
            created = modified
        if created is not None:
            directory.created_at = created
        if modified is not None:
            directory.modified_at = modified

    def _process_contents(
        self, contents: list[ContentFile] | ContentFile, parent_dir: GithubDirectory
    ) -> None:
        if not isinstance(contents, list):
            contents = [contents]

        for content in contents:
            if content.type == "dir":
                child_dir = self._create_child_dir(content.name, parent_dir)
                self._restore_dir_timestamps(child_dir, content.path)
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
                    file_name, message_id = content.name.rsplit(".", 1)
                    TGFSDirectory.create_file_ref(
                        parent_dir, file_name, int(message_id)
                    )
                except ValueError:
                    logger.warning(
                        f"Invalid name format for {content.name}, expected a format like 'name.message_id'"
                    )
