import logging
from dataclasses import dataclass
from typing import Optional

from github import Github, InputGitTreeElement
from github.Repository import Repository

from tgfs.core.model import TGFSDirectory, TGFSFileRef
from tgfs.crypto.path_names import encrypt_path_name

logger = logging.getLogger(__name__)


@dataclass
class GithubConfig:
    gh: Github
    repo_name: str
    repo: Repository
    commit: str
    # Deterministic AES-SIV key for path-name encryption. ``None`` keeps the
    # legacy behaviour of storing plaintext directory/file names in the repo.
    name_key: Optional[bytes] = None


class GithubDirectory(TGFSDirectory):
    def __init__(
        self,
        ghc: GithubConfig,
        name: str,
        parent: Optional[TGFSDirectory],
        children: Optional[list[TGFSDirectory]] = None,
        files: Optional[list[TGFSFileRef]] = None,
        stored_encrypted: Optional[bool] = None,
    ):
        super().__init__(name, parent, children or [], files or [])
        self._ghc = ghc
        # Whether THIS directory is stored under an encrypted name in the
        # repo. New directories follow the configured key; directories loaded
        # from the repo carry whatever form they were found in, so encrypted
        # and legacy-plaintext folders can be read and written side by side.
        self._stored_encrypted = (
            stored_encrypted
            if stored_encrypted is not None
            else ghc.name_key is not None
        )

    @staticmethod
    def join_path(*args: str) -> str:
        """Join paths in a way that is compatible with GitHub"""
        return "/".join(part.strip("/") for part in args if part)

    @property
    def _storage_name(self) -> str:
        """The on-repo name of this directory (encrypted when applicable)."""
        key = self._ghc.name_key
        if key is not None and self._stored_encrypted:
            return encrypt_path_name(key, self.name)
        return self.name

    def _file_ref_storage_name(self, name: str, message_id: int) -> str:
        """On-repo filename ``<name>.<id>``, with ``<name>`` encrypted if keyed."""
        key = self._ghc.name_key
        if key is not None:
            return f"{encrypt_path_name(key, name)}.{message_id}"
        return f"{name}.{message_id}"

    @property
    def _github_path(self) -> str:
        """Get the GitHub repository path for this directory"""
        if self.parent is None:
            return ""

        if isinstance(self.parent, GithubDirectory):
            parent_path = self.parent._github_path
        else:
            parent_path = ""

        return self.join_path(parent_path, self._storage_name)

    def create_dir_skip_github_ops(self, name: str) -> "GithubDirectory":
        res = GithubDirectory(self._ghc, name, self)
        self.children.append(res)
        return res

    def create_dir(
        self, name: str, dir_to_copy: Optional[TGFSDirectory] = None
    ) -> "GithubDirectory":
        child = super().create_dir(name, dir_to_copy)

        # Create directory in GitHub by creating a placeholder file. The new
        # directory follows the configured key, so its on-repo segment is the
        # encrypted name when path-name encryption is enabled.
        key = self._ghc.name_key
        child_segment = encrypt_path_name(key, name) if key is not None else name
        dir_path = self.join_path(self._github_path, child_segment, ".gitkeep")
        try:
            self._ghc.repo.create_file(
                path=dir_path,
                message=f"Create directory {name}",
                content="",
                branch=self._ghc.commit,
            )
            logger.info(f"Created directory {name} in GitHub repository at {dir_path}")
        except Exception as ex:
            logger.error(f"Failed to create directory {name} in GitHub: {ex}")
            self.children.remove(child)
            raise

        # Convert the child to GithubDirectory
        github_child = GithubDirectory(
            ghc=self._ghc,
            name=child.name,
            parent=self,
            children=child.children,
            files=child.files,
        )

        # Replace the child in the parent's children list
        child_index = self.children.index(child)
        self.children[child_index] = github_child

        return github_child

    def delete(self) -> None:
        if self.parent:
            # Remove all files and subdirectories from GitHub
            self._delete_github_directory()
        super().delete()

    def create_file_ref(self, name: str, file_message_id: int) -> TGFSFileRef:
        file_ref = super().create_file_ref(name, file_message_id)

        # Create file reference in GitHub (filename encrypted when keyed)
        file_path = self.join_path(
            self._github_path, self._file_ref_storage_name(name, file_message_id)
        )
        try:
            self._ghc.repo.create_file(
                path=file_path,
                message=f"Create file reference for {name}",
                content="",
                branch=self._ghc.commit,
            )
            logger.info(
                f"Created file reference {name} in {self._ghc.repo_name} at {file_path}"
            )
        except Exception as ex:
            logger.error(
                f"Failed to create file reference {name} in {self._ghc.repo_name}: {ex}"
            )
            self.files.remove(file_ref)
            raise

        return file_ref

    def delete_file_ref(self, fr: TGFSFileRef) -> None:
        # The ref may be stored under its encrypted or its legacy-plaintext
        # name (mixed repos), so try the encrypted form first, then plaintext.
        candidates = []
        if self._ghc.name_key is not None:
            candidates.append(self._file_ref_storage_name(fr.name, fr.message_id))
        candidates.append(f"{fr.name}.{fr.message_id}")

        for segment in dict.fromkeys(candidates):  # de-dup, keep order
            file_path = self.join_path(self._github_path, segment)
            try:
                file_content = self._ghc.repo.get_contents(
                    file_path, ref=self._ghc.commit
                )
                if isinstance(file_content, list):
                    file_content = file_content[0]
                self._ghc.repo.delete_file(
                    path=file_path,
                    message=f"Delete file reference for {fr.name}",
                    sha=file_content.sha,
                    branch=self._ghc.commit,
                )
                logger.info(
                    f"Deleted file reference {fr.name} from {self._ghc.repo_name}"
                )
                break
            except Exception as ex:
                logger.debug(
                    f"Could not delete {file_path} from {self._ghc.repo_name}: {ex}"
                )
        else:
            logger.error(
                f"Failed to delete file reference {fr.name} "
                f"from {self._ghc.repo_name}: not found"
            )

        super().delete_file_ref(fr)

    def _delete_github_directory(self) -> None:
        """Remove this directory and everything beneath it in one commit.

        ``delete_file`` can only remove a single file — it returns HTTP 422
        on a subtree — so a per-entry delete cannot recurse into
        subdirectories (their nested ``.gitkeep`` and files would survive).
        Instead we rewrite the git tree without any blob under this
        directory's path, dropping arbitrarily-nested content atomically in
        a single commit via the Git Data API.
        """
        prefix = self._github_path
        if not prefix:
            return  # guard: never wipe the whole repo via the root
        try:
            ref = self._ghc.repo.get_git_ref(f"heads/{self._ghc.commit}")
            base_commit = self._ghc.repo.get_git_commit(ref.object.sha)
            tree = self._ghc.repo.get_git_tree(base_commit.tree.sha, recursive=True)

            kept: list[InputGitTreeElement] = []
            removed = 0
            for entry in tree.tree:
                if entry.type != "blob":
                    continue
                if entry.path == prefix or entry.path.startswith(prefix + "/"):
                    removed += 1
                    continue
                kept.append(
                    InputGitTreeElement(
                        path=entry.path,
                        mode=entry.mode,
                        type="blob",
                        sha=entry.sha,
                    )
                )

            if removed == 0:
                return

            new_tree = self._ghc.repo.create_git_tree(kept)
            new_commit = self._ghc.repo.create_git_commit(
                f"Delete directory {prefix}", new_tree, [base_commit]
            )
            ref.edit(new_commit.sha)
            logger.info(
                f"Deleted {removed} object(s) under {prefix} "
                f"from {self._ghc.repo_name}"
            )
        except Exception as ex:
            logger.error(
                f"Failed to delete directory {prefix} "
                f"from {self._ghc.repo_name}: {ex}"
            )
