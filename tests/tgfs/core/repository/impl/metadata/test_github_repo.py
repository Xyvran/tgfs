import datetime
import json

import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import List
from github import Github
from github.Repository import Repository
from github.ContentFile import ContentFile
from github.GitTreeElement import GitTreeElement

from tgfs.config import GithubRepoConfig
from tgfs.core.model import TGFSDirectory, TGFSFileRef, TGFSMetadata
from tgfs.core.repository.impl.metadata.github_repo import GithubRepoMetadataRepository
from tgfs.core.repository.impl.metadata.github_repo.dir_timestamps import (
    CACHE_VERSION,
    DirTimestampStore,
)
from tgfs.core.repository.impl.metadata.github_repo.gh_directory import (
    GithubConfig,
    GithubDirectory,
)


def mock_tree(repo, paths, truncated=False):
    """Make ``get_git_tree`` answer with ``paths``; a trailing ``/`` is a subtree.

    The load reads the whole repo in one recursive tree call, so this is what
    the structure tests below have to stand in for.
    """
    entries = []
    for path in paths:
        entry = Mock(spec=GitTreeElement)
        entry.path = path.rstrip("/")
        entry.type = "tree" if path.endswith("/") else "blob"
        entries.append(entry)

    tree = Mock()
    tree.tree = entries
    tree.truncated = truncated
    repo.get_git_tree.return_value = tree
    return tree


@pytest.fixture(autouse=True)
def stub_timestamp_store():
    """Keep the date cache out of the structure tests.

    A real store would start background workers against the mocked repo and
    write a cache file into the caller's home directory. Its own behaviour is
    covered in ``test_dir_timestamps.py``.
    """
    with patch(
        "tgfs.core.repository.impl.metadata.github_repo.DirTimestampStore"
    ) as store_cls:
        store = Mock(spec=DirTimestampStore)
        store.get.return_value = None  # every lookup misses
        store_cls.return_value = store
        yield store


# Global fixtures for all test classes
@pytest.fixture
def mock_github_config():
    """Create a mock GitHub configuration"""
    return GithubRepoConfig(
        access_token="test_token", repo="owner/test-repo", commit="main"
    )


@pytest.fixture
def mock_github():
    """Mock Github client"""
    github = Mock(spec=Github)
    return github


@pytest.fixture
def mock_repo():
    """Mock GitHub repository"""
    repo = Mock(spec=Repository)
    repo.name = "test-repo"
    repo.full_name = "owner/test-repo"
    return repo


@pytest.fixture
def mock_ghc(mock_github, mock_repo):
    """Mock GithubConfig"""
    return GithubConfig(
        gh=mock_github, repo_name="owner/test-repo", repo=mock_repo, commit="main"
    )


@pytest.fixture
def sample_content_file():
    """Create a sample ContentFile mock"""
    content = Mock(spec=ContentFile)
    content.name = "test_file.12345"
    content.path = "test_file.12345"
    content.type = "file"
    content.sha = "abc123"
    return content


@pytest.fixture
def sample_directory_content():
    """Create a sample directory ContentFile mock"""
    content = Mock(spec=ContentFile)
    content.name = "test_dir"
    content.path = "test_dir"
    content.type = "dir"
    return content


class TestGithubRepoMetadataRepository:
    """Test the main GithubRepoMetadataRepository class"""

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_init_with_config(self, mock_github_class, mock_github_config):
        """Test repository initialization with GitHub config"""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        repository = GithubRepoMetadataRepository(mock_github_config)

        mock_github_class.assert_called_once_with("test_token")
        mock_github_instance.get_repo.assert_called_once_with("owner/test-repo")
        assert repository._ghc.repo_name == "owner/test-repo"
        assert repository._ghc.commit == "main"
        assert repository._ghc.repo == mock_repo
        assert repository._ghc.gh == mock_github_instance

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    @pytest.mark.asyncio
    async def test_get_metadata(self, mock_github_class, mock_github_config):
        """Test getting metadata structure"""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        # Mock the repo contents
        mock_tree(mock_repo, [])

        repository = GithubRepoMetadataRepository(mock_github_config)

        # Test get method
        result = await repository.get()

        # Should return TGFSMetadata with GithubDirectory
        assert isinstance(result, TGFSMetadata)
        assert isinstance(result.dir, GithubDirectory)
        assert result.dir.name == "root"
        assert result.dir.parent is None

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_build_directory_structure_restores_root_timestamps(
        self, mock_github_class, mock_github_config
    ):
        """Root directory dates come from the backing repo's own metadata."""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        created = datetime.datetime(2025, 1, 2, 9, 0, tzinfo=datetime.timezone.utc)
        pushed = datetime.datetime(2026, 6, 1, 18, 0, tzinfo=datetime.timezone.utc)
        mock_repo.created_at = created
        mock_repo.pushed_at = pushed
        mock_tree(mock_repo, [])

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        assert root_dir.created_at == created
        assert root_dir.modified_at == pushed

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_build_directory_structure_with_files_and_dirs(
        self, mock_github_class, mock_github_config
    ):
        """Test building directory structure with files and directories"""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        # root -> [document.123, subdir] -> [image.456]
        mock_tree(mock_repo, ["document.123", "subdir/", "subdir/image.456"])

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        # Verify structure
        assert root_dir.name == "root"
        assert len(root_dir.files) == 1
        assert len(root_dir.children) == 1

        # Check root file
        assert root_dir.files[0].name == "document"
        assert root_dir.files[0].message_id == 123

        # Check subdirectory
        sub_dir = root_dir.children[0]
        assert sub_dir.name == "subdir"
        assert len(sub_dir.files) == 1
        assert sub_dir.files[0].name == "image"
        assert sub_dir.files[0].message_id == 456

        # The whole repo came from one recursive tree call, not one call per
        # directory -- that is the point of the change.
        mock_repo.get_git_tree.assert_called_once_with("main", recursive=True)
        mock_repo.get_contents.assert_not_called()

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_tree_walk_creates_missing_parent_directories(
        self, mock_github_class, mock_github_config
    ):
        """A blob can arrive before the subtrees above it exist."""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        # Only the blob is listed: both directories have to be inferred from
        # its path, and in this order.
        mock_tree(mock_repo, ["Serien/Heat/episode.9"])

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        assert [c.name for c in root_dir.children] == ["Serien"]
        serien = root_dir.children[0]
        assert [c.name for c in serien.children] == ["Heat"]
        heat = serien.children[0]
        assert [(f.name, f.message_id) for f in heat.files] == [("episode", 9)]

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_tree_entries_are_not_duplicated(
        self, mock_github_class, mock_github_config
    ):
        """A subtree listed after its children is still created only once."""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        mock_tree(mock_repo, ["Serien/Heat/episode.9", "Serien/", "Serien/Heat/"])

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        assert len(root_dir.children) == 1
        assert len(root_dir.children[0].children) == 1

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_directory_timestamps_come_from_the_cache(
        self, mock_github_class, mock_github_config, tmp_path
    ):
        """A warm cache dates every directory without touching git history."""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_repo.full_name = "owner/test-repo"
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        mock_tree(mock_repo, ["Serien/", "Serien/.gitkeep"])

        created = datetime.datetime(2024, 3, 1, 12, 0, tzinfo=datetime.timezone.utc)
        modified = datetime.datetime(2025, 7, 4, 8, 30, tzinfo=datetime.timezone.utc)
        cache = tmp_path / "dir-timestamps.json"
        cache.write_text(
            json.dumps(
                {
                    "version": CACHE_VERSION,
                    "repo": "owner/test-repo",
                    "branch": "main",
                    "head": "cafe1234",
                    "paths": {
                        "Serien": {
                            "created": created.isoformat(),
                            "modified": modified.isoformat(),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        # The head has not moved, so the cache is taken as-is.
        mock_repo.get_branch.return_value.commit.sha = "cafe1234"

        repository = GithubRepoMetadataRepository(mock_github_config)
        store = DirTimestampStore(repo=mock_repo, branch="main", path=str(cache))
        repository._timestamps = store
        repository._ghc.timestamps = store
        store.load()

        root_dir = repository._build_directory_structure()

        sub_dir = root_dir.children[0]
        assert sub_dir.created_at == created
        assert sub_dir.modified_at == modified
        # No git history was read and no diff was needed to get there.
        mock_repo.get_commits.assert_not_called()
        mock_repo.compare.assert_not_called()

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_reads_encrypted_and_legacy_names(
        self, mock_github_class, mock_github_config
    ):
        """Encrypted dir/file names are decrypted; plaintext ones pass through."""
        from tgfs.crypto.path_names import (
            derive_path_name_key,
            encrypt_path_name,
        )

        key = derive_path_name_key(b"\x42" * 32)

        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        enc_dir = encrypt_path_name(key, "Filme")
        enc_file = encrypt_path_name(key, "movie.mp4")

        mock_tree(
            mock_repo,
            [
                f"{enc_dir}/",
                "legacy.7",
                f"{enc_dir}/{enc_file}.39",
            ],
        )

        repository = GithubRepoMetadataRepository(
            mock_github_config, name_key=key
        )
        root = repository._build_directory_structure()

        # Legacy plaintext file at root passes through unchanged.
        assert {f.name for f in root.files} == {"legacy"}
        # Encrypted directory name is decrypted in the model.
        assert len(root.children) == 1
        filme = root.children[0]
        assert filme.name == "Filme"
        # Encrypted file name inside it is decrypted too.
        assert {f.name for f in filme.files} == {"movie.mp4"}

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_build_directory_structure_with_gitkeep_ignored(
        self, mock_github_class, mock_github_config
    ):
        """Test that .gitkeep files are ignored during structure building"""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        mock_tree(
            mock_repo,
            [".gitkeep", "test.789", "subdir/", "subdir/.gitkeep"],
        )

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        # Should only have the regular file, .gitkeep should be ignored
        assert len(root_dir.files) == 1
        assert root_dir.files[0].name == "test"
        assert root_dir.files[0].message_id == 789
        # The placeholder inside the subdirectory is dropped as well.
        assert len(root_dir.children) == 1
        assert root_dir.children[0].files == []

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    @patch("tgfs.core.repository.impl.metadata.github_repo.logger")
    def test_build_directory_structure_handles_invalid_filename(
        self, mock_logger, mock_github_class, mock_github_config
    ):
        """Test handling of invalid filename formats"""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        mock_tree(mock_repo, ["invalid_filename_no_message_id"])

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        # Should have no files due to invalid format
        assert len(root_dir.files) == 0

        # Should log a warning
        mock_logger.warning.assert_called_once()
        warning_call = mock_logger.warning.call_args[0][0]
        assert "Invalid name format" in warning_call
        assert "invalid_filename_no_message_id" in warning_call

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    @patch("tgfs.core.repository.impl.metadata.github_repo.logger")
    def test_build_directory_structure_handles_repo_errors(
        self, mock_logger, mock_github_class, mock_github_config
    ):
        """Test handling of repository access errors"""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        # Both the tree call and the walk it falls back to are refused
        mock_repo.get_git_tree.side_effect = Exception("API rate limit exceeded")
        mock_repo.get_contents.side_effect = Exception("API rate limit exceeded")

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        # Should return empty root directory
        assert root_dir.name == "root"
        assert len(root_dir.files) == 0
        assert len(root_dir.children) == 0

        # Should log error
        mock_logger.error.assert_called_once()

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_unreadable_tree_falls_back_to_the_directory_walk(
        self, mock_github_class, mock_github_config
    ):
        """A failing tree call must not cost the filesystem its contents."""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        mock_repo.get_git_tree.side_effect = Exception("server error")

        subdir = Mock(spec=ContentFile)
        subdir.name, subdir.type, subdir.path = "Serien", "dir", "Serien"
        inner = Mock(spec=ContentFile)
        inner.name, inner.type, inner.path = "ep.5", "file", "Serien/ep.5"
        mock_repo.get_contents.side_effect = [[subdir], [inner]]

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        assert [c.name for c in root_dir.children] == ["Serien"]
        assert [f.name for f in root_dir.children[0].files] == ["ep"]

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_truncated_tree_falls_back_to_the_directory_walk(
        self, mock_github_class, mock_github_config
    ):
        """A truncated tree would hide whole folders, so it is refused."""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        # The tree lists one directory but is incomplete; the walk sees two.
        mock_tree(mock_repo, ["Serien/"], truncated=True)

        first = Mock(spec=ContentFile)
        first.name, first.type, first.path = "Serien", "dir", "Serien"
        second = Mock(spec=ContentFile)
        second.name, second.type, second.path = "Filme", "dir", "Filme"
        mock_repo.get_contents.side_effect = [[first, second], [], []]

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        assert [c.name for c in root_dir.children] == ["Serien", "Filme"]

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    @patch("tgfs.core.repository.impl.metadata.github_repo.logger")
    def test_build_directory_structure_handles_subdirectory_errors(
        self, mock_logger, mock_github_class, mock_github_config
    ):
        """Test handling of subdirectory access errors"""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        subdir = Mock(spec=ContentFile)
        subdir.name = "protected_dir"
        subdir.type = "dir"
        subdir.path = "protected_dir"

        # No usable tree, so the walk runs: root succeeds, the subdir fails
        mock_repo.get_git_tree.side_effect = Exception("server error")
        mock_repo.get_contents.side_effect = [
            [subdir],  # root contents
            Exception("Access denied"),  # subdirectory contents
        ]

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        # Should have the directory but it will be empty
        assert len(root_dir.children) == 1
        assert root_dir.children[0].name == "protected_dir"
        assert len(root_dir.children[0].files) == 0

        # Should log warning
        warnings = [call[0][0] for call in mock_logger.warning.call_args_list]
        assert any("Failed to construct directory protected_dir" in w for w in warnings)

    @pytest.mark.asyncio
    async def test_push_method(self, mock_github_config):
        """Test push method (currently no-op)"""
        with patch("tgfs.core.repository.impl.metadata.github_repo.Github"):
            repository = GithubRepoMetadataRepository(mock_github_config)
            # Should not raise any exception
            await repository.push()


class TestGithubDirectory:
    """Test the GithubDirectory class functionality"""

    def test_join_path_method(self):
        """Test path joining utility method"""
        # Test normal case
        result = GithubDirectory.join_path("folder1", "folder2", "file.txt")
        assert result == "folder1/folder2/file.txt"

        # Test with leading/trailing slashes
        result = GithubDirectory.join_path("/folder1/", "/folder2/", "/file.txt/")
        assert result == "folder1/folder2/file.txt"

        # Test with empty parts
        result = GithubDirectory.join_path("folder1", "", "folder2", "file.txt")
        assert result == "folder1/folder2/file.txt"

        # Test single path
        result = GithubDirectory.join_path("single")
        assert result == "single"

        # Test empty
        result = GithubDirectory.join_path()
        assert result == ""

    def test_github_path_property(self, mock_ghc):
        """Test GitHub path property calculation"""
        # Root directory
        root_dir = GithubDirectory(mock_ghc, "root", None)
        assert root_dir._github_path == ""

        # First level subdirectory
        sub_dir = GithubDirectory(mock_ghc, "subfolder", root_dir)
        assert sub_dir._github_path == "subfolder"

        # Nested subdirectory
        nested_dir = GithubDirectory(mock_ghc, "nested", sub_dir)
        assert nested_dir._github_path == "subfolder/nested"

    def test_init_with_defaults(self, mock_ghc):
        """Test GithubDirectory initialization with default values"""
        directory = GithubDirectory(mock_ghc, "test", None)

        assert directory.name == "test"
        assert directory.parent is None
        assert directory.children == []
        assert directory.files == []
        assert directory._ghc == mock_ghc

    def test_init_with_explicit_values(self, mock_ghc):
        """Test GithubDirectory initialization with explicit values"""
        children: List[TGFSDirectory] = [Mock()]
        files: List[TGFSFileRef] = [Mock()]
        parent = Mock()

        directory = GithubDirectory(mock_ghc, "test", parent, children, files)

        assert directory.name == "test"
        assert directory.parent == parent
        assert directory.children == children
        assert directory.files == files

    def test_create_dir_skip_github_ops(self, mock_ghc):
        """Test creating directory without GitHub operations"""
        parent_dir = GithubDirectory(mock_ghc, "parent", None)

        child_dir = parent_dir.create_dir_skip_github_ops("child")

        assert isinstance(child_dir, GithubDirectory)
        assert child_dir.name == "child"
        assert child_dir.parent == parent_dir
        assert child_dir in parent_dir.children
        assert child_dir._ghc == mock_ghc

    def test_create_dir_with_github_ops_success(self, mock_ghc):
        """Test creating directory with successful GitHub operations"""
        mock_ghc.repo.create_file.return_value = Mock()

        parent_dir = GithubDirectory(mock_ghc, "parent", None)
        child_dir = parent_dir.create_dir("child")

        # Verify GitHub API call - parent dir has None parent so path is just "child/.gitkeep"
        mock_ghc.repo.create_file.assert_called_once_with(
            path="child/.gitkeep",
            message="Create directory child",
            content="",
            branch="main",
        )

        # Verify directory structure
        assert isinstance(child_dir, GithubDirectory)
        assert child_dir.name == "child"
        assert child_dir.parent == parent_dir
        assert child_dir in parent_dir.children

    def test_create_dir_encrypts_path_when_keyed(self, mock_ghc):
        """With a name key, the on-repo directory segment is encrypted."""
        from tgfs.crypto.path_names import (
            decrypt_path_name,
            derive_path_name_key,
            is_encrypted_path_name,
        )

        key = derive_path_name_key(b"\x42" * 32)
        mock_ghc.name_key = key
        mock_ghc.repo.create_file.return_value = Mock()

        parent_dir = GithubDirectory(mock_ghc, "root", None)
        parent_dir.create_dir("Filme")

        path = mock_ghc.repo.create_file.call_args.kwargs["path"]
        assert path.endswith("/.gitkeep")
        segment = path[: -len("/.gitkeep")]
        assert is_encrypted_path_name(segment)
        assert decrypt_path_name(key, segment) == "Filme"

    def test_create_file_ref_encrypts_name_when_keyed(self, mock_ghc):
        """With a name key, the on-repo file segment is <enc(name)>.<id>."""
        from tgfs.crypto.path_names import (
            decrypt_path_name,
            derive_path_name_key,
            is_encrypted_path_name,
        )

        key = derive_path_name_key(b"\x42" * 32)
        mock_ghc.name_key = key
        mock_ghc.repo.create_file.return_value = Mock()

        directory = GithubDirectory(mock_ghc, "root", None, stored_encrypted=True)
        directory.create_file_ref("movie.mp4", 39)

        path = mock_ghc.repo.create_file.call_args.kwargs["path"]
        enc_name, message_id = path.rsplit(".", 1)
        assert message_id == "39"
        assert is_encrypted_path_name(enc_name)
        assert decrypt_path_name(key, enc_name) == "movie.mp4"

    def test_create_dir_with_github_ops_failure(self, mock_ghc):
        """Test creating directory with GitHub operation failure"""
        mock_ghc.repo.create_file.side_effect = Exception("GitHub API error")

        parent_dir = GithubDirectory(mock_ghc, "parent", None)

        with pytest.raises(Exception, match="GitHub API error"):
            parent_dir.create_dir("child")

        # Verify no directory was added to parent
        assert len(parent_dir.children) == 0

    def test_create_file_ref_success(self, mock_ghc):
        """Test creating file reference with successful GitHub operations"""
        mock_ghc.repo.create_file.return_value = Mock()

        directory = GithubDirectory(mock_ghc, "testdir", None)
        file_ref = directory.create_file_ref("testfile", 12345)

        # Verify GitHub API call - directory has None parent so path is just the filename
        mock_ghc.repo.create_file.assert_called_once_with(
            path="testfile.12345",
            message="Create file reference for testfile",
            content="",
            branch="main",
        )

        # Verify file reference
        assert isinstance(file_ref, TGFSFileRef)
        assert file_ref.name == "testfile"
        assert file_ref.message_id == 12345
        assert file_ref in directory.files

    def test_create_file_ref_failure(self, mock_ghc):
        """Test creating file reference with GitHub operation failure"""
        mock_ghc.repo.create_file.side_effect = Exception("GitHub API error")

        directory = GithubDirectory(mock_ghc, "testdir", None)

        with pytest.raises(Exception, match="GitHub API error"):
            directory.create_file_ref("testfile", 12345)

        # Verify no file was added
        assert len(directory.files) == 0

    def test_delete_file_ref_success(self, mock_ghc):
        """Test deleting file reference with successful GitHub operations"""
        mock_content = Mock()
        mock_content.sha = "abc123"
        mock_ghc.repo.get_contents.return_value = mock_content
        mock_ghc.repo.delete_file.return_value = Mock()

        directory = GithubDirectory(mock_ghc, "testdir", None)

        # Create file ref using parent class method (which creates it properly)
        from tgfs.core.model import TGFSFileRef

        file_ref = TGFSFileRef(message_id=12345, name="testfile", location=directory)
        directory.files.append(file_ref)

        directory.delete_file_ref(file_ref)

        # Verify GitHub API calls - directory has None parent so paths are just the filenames
        mock_ghc.repo.get_contents.assert_called_once_with("testfile.12345", ref="main")
        mock_ghc.repo.delete_file.assert_called_once_with(
            path="testfile.12345",
            message="Delete file reference for testfile",
            sha="abc123",
            branch="main",
        )

        # Verify file was removed
        assert file_ref not in directory.files

    def test_delete_file_ref_with_list_content(self, mock_ghc):
        """Test deleting file reference when get_contents returns a list"""
        mock_content = Mock()
        mock_content.sha = "abc123"
        mock_ghc.repo.get_contents.return_value = [
            mock_content
        ]  # List instead of single item
        mock_ghc.repo.delete_file.return_value = Mock()

        directory = GithubDirectory(mock_ghc, "testdir", None)
        file_ref = TGFSFileRef(message_id=12345, name="testfile", location=directory)
        directory.files.append(file_ref)

        directory.delete_file_ref(file_ref)

        # Should use first item from the list - directory has None parent
        mock_ghc.repo.delete_file.assert_called_once_with(
            path="testfile.12345",
            message="Delete file reference for testfile",
            sha="abc123",
            branch="main",
        )

    @patch("tgfs.core.repository.impl.metadata.github_repo.gh_directory.logger")
    def test_delete_file_ref_failure(self, mock_logger, mock_ghc):
        """Test deleting file reference with GitHub operation failure"""
        mock_ghc.repo.get_contents.side_effect = Exception("File not found")

        directory = GithubDirectory(mock_ghc, "testdir", None)
        file_ref = TGFSFileRef(message_id=12345, name="testfile", location=directory)
        directory.files.append(file_ref)

        directory.delete_file_ref(file_ref)

        # Should log error but continue
        mock_logger.error.assert_called_once()
        error_call = mock_logger.error.call_args[0][0]
        assert "Failed to delete file reference testfile" in error_call

        # File should still be removed from local structure
        assert file_ref not in directory.files

    def test_delete_directory(self, mock_ghc):
        """Deleting a directory rewrites the tree without its whole subtree."""

        def blob(path):
            e = Mock()
            e.path, e.type, e.sha, e.mode = path, "blob", path + "-sha", "100644"
            return e

        subtree = Mock()
        subtree.path, subtree.type = "testdir/sub", "tree"

        entries = [
            blob("testdir/.gitkeep"),
            blob("testdir/sub/.gitkeep"),  # nested -> must also be removed
            subtree,  # a tree entry -> ignored
            blob("other/.gitkeep"),  # unrelated -> must be kept
        ]

        ref = Mock()
        ref.object.sha = "commitsha"
        base_commit = Mock()
        base_commit.tree.sha = "basetreesha"
        tree = Mock()
        tree.tree = entries
        new_commit = Mock()
        new_commit.sha = "newcommitsha"

        mock_ghc.repo.get_git_ref.return_value = ref
        mock_ghc.repo.get_git_commit.return_value = base_commit
        mock_ghc.repo.get_git_tree.return_value = tree
        mock_ghc.repo.create_git_tree.return_value = Mock()
        mock_ghc.repo.create_git_commit.return_value = new_commit

        parent = Mock()
        parent.children = []
        directory = GithubDirectory(mock_ghc, "testdir", parent)
        parent.children.append(directory)

        directory.delete()

        # New tree keeps only the unrelated blob (both testdir blobs dropped).
        kept = mock_ghc.repo.create_git_tree.call_args[0][0]
        assert len(kept) == 1
        mock_ghc.repo.get_git_tree.assert_called_once_with(
            "basetreesha", recursive=True
        )
        ref.edit.assert_called_once_with("newcommitsha")
        assert directory not in parent.children

    @patch("tgfs.core.repository.impl.metadata.github_repo.gh_directory.logger")
    def test_delete_directory_handles_errors(self, mock_logger, mock_ghc):
        """Test deleting directory with error handling"""
        mock_ghc.repo.get_git_ref.side_effect = Exception("Access denied")

        parent = Mock()
        parent.children = []

        directory = GithubDirectory(mock_ghc, "testdir", parent)
        parent.children.append(directory)

        directory.delete()

        # Should log error
        mock_logger.error.assert_called_once()
        error_call = mock_logger.error.call_args[0][0]
        assert "Failed to delete directory testdir" in error_call

        # Directory should still be removed from parent
        assert directory not in parent.children

    def test_move_directory(self, mock_ghc):
        """Moving a directory re-paths its whole subtree in one commit."""

        def blob(path):
            e = Mock()
            e.path, e.type, e.sha, e.mode = path, "blob", path + "-sha", "100644"
            return e

        subtree = Mock()
        subtree.path, subtree.type = "src/moving/sub", "tree"

        entries = [
            blob("src/moving/.gitkeep"),
            blob("src/moving/sub/.gitkeep"),  # nested -> must move along
            blob("src/moving/sub/note.txt.7"),
            subtree,  # a tree entry -> ignored
            blob("other/.gitkeep"),  # unrelated -> must keep its path
        ]

        ref = Mock()
        ref.object.sha = "commitsha"
        base_commit = Mock()
        base_commit.tree.sha = "basetreesha"
        tree = Mock()
        tree.tree = entries
        new_commit = Mock()
        new_commit.sha = "newcommitsha"

        mock_ghc.repo.get_git_ref.return_value = ref
        mock_ghc.repo.get_git_commit.return_value = base_commit
        mock_ghc.repo.get_git_tree.return_value = tree
        mock_ghc.repo.create_git_tree.return_value = Mock()
        mock_ghc.repo.create_git_commit.return_value = new_commit

        root = GithubDirectory(mock_ghc, "root", None)
        src = GithubDirectory(mock_ghc, "src", root)
        dest = GithubDirectory(mock_ghc, "dest", root)
        root.children.extend([src, dest])
        moving = GithubDirectory(mock_ghc, "moving", src)
        src.children.append(moving)

        moving.move_to(dest)

        elements = mock_ghc.repo.create_git_tree.call_args[0][0]
        assert sorted(e._identity["path"] for e in elements) == [
            "dest/moving/.gitkeep",
            "dest/moving/sub/.gitkeep",
            "dest/moving/sub/note.txt.7",
            "other/.gitkeep",
        ]
        ref.edit.assert_called_once_with("newcommitsha")
        assert dest.children == [moving]
        assert src.children == []

    def test_move_directory_rolls_back_when_the_repo_write_fails(self, mock_ghc):
        mock_ghc.repo.get_git_ref.side_effect = Exception("Access denied")

        root = GithubDirectory(mock_ghc, "root", None)
        src = GithubDirectory(mock_ghc, "src", root)
        dest = GithubDirectory(mock_ghc, "dest", root)
        root.children.extend([src, dest])
        moving = GithubDirectory(mock_ghc, "moving", src)
        src.children.append(moving)

        with pytest.raises(Exception, match="Access denied"):
            moving.move_to(dest)

        # The repo is the metadata, so a move it did not record must not stick.
        assert moving.parent is src
        assert src.children == [moving]
        assert dest.children == []


class TestGithubConfig:
    """Test the GithubConfig dataclass"""

    def test_github_config_creation(self):
        """Test creating GithubConfig"""
        gh = Mock(spec=Github)
        repo = Mock(spec=Repository)

        config = GithubConfig(gh=gh, repo_name="owner/repo", repo=repo, commit="main")

        assert config.gh == gh
        assert config.repo_name == "owner/repo"
        assert config.repo == repo
        assert config.commit == "main"


class TestIntegrationScenarios:
    """Integration tests for complete workflows"""

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    @pytest.mark.asyncio
    async def test_complete_workflow_file_operations(
        self, mock_github_class, mock_github_config
    ):
        """Test complete workflow of creating and managing files"""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        # Mock initial empty repository
        mock_tree(mock_repo, [])

        repository = GithubRepoMetadataRepository(mock_github_config)
        metadata = await repository.get()
        root_dir = metadata.dir

        # Create a subdirectory
        mock_repo.create_file.return_value = Mock()
        sub_dir = root_dir.create_dir("documents")

        # Create file references
        file_ref1 = sub_dir.create_file_ref("report", 11111)
        file_ref2 = sub_dir.create_file_ref("presentation", 22222)

        # Verify structure
        assert len(root_dir.children) == 1
        assert len(sub_dir.files) == 2
        assert file_ref1.name == "report"
        assert file_ref2.name == "presentation"

        # Delete a file
        mock_content = Mock()
        mock_content.sha = "abc123"
        mock_repo.get_contents.return_value = mock_content
        sub_dir.delete_file_ref(file_ref1)

        assert len(sub_dir.files) == 1
        assert file_ref1 not in sub_dir.files

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_complex_directory_structure_building(
        self, mock_github_class, mock_github_config
    ):
        """Test building complex nested directory structures"""
        mock_github_instance = Mock(spec=Github)
        mock_repo = Mock(spec=Repository)
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_github_instance

        # Complex structure: root/docs/2023/reports/ with files
        mock_tree(
            mock_repo,
            [
                "docs/",
                "docs/2023/",
                "docs/2023/reports/",
                "docs/2023/reports/q1_report.111",
                "docs/2023/reports/q2_report.222",
            ],
        )

        repository = GithubRepoMetadataRepository(mock_github_config)
        root_dir = repository._build_directory_structure()

        # Navigate and verify structure
        assert len(root_dir.children) == 1
        docs = root_dir.children[0]
        assert docs.name == "docs"

        assert len(docs.children) == 1
        year_2023 = docs.children[0]
        assert year_2023.name == "2023"

        assert len(year_2023.children) == 1
        reports = year_2023.children[0]
        assert reports.name == "reports"

        assert len(reports.files) == 2
        file_names = {f.name for f in reports.files}
        assert file_names == {"q1_report", "q2_report"}

        message_ids = {f.message_id for f in reports.files}
        assert message_ids == {111, 222}


class TestErrorHandling:
    """Test error handling scenarios"""

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_invalid_github_token(self, mock_github_class, mock_github_config):
        """Test handling of invalid GitHub token"""
        mock_github_class.side_effect = Exception("Bad credentials")

        with pytest.raises(Exception, match="Bad credentials"):
            GithubRepoMetadataRepository(mock_github_config)

    @patch("tgfs.core.repository.impl.metadata.github_repo.Github")
    def test_invalid_repository(self, mock_github_class, mock_github_config):
        """Test handling of invalid repository"""
        mock_github_instance = Mock(spec=Github)
        mock_github_instance.get_repo.side_effect = Exception("Repository not found")
        mock_github_class.return_value = mock_github_instance

        with pytest.raises(Exception, match="Repository not found"):
            GithubRepoMetadataRepository(mock_github_config)

    def test_file_ref_with_non_numeric_message_id(self, mock_ghc):
        """Test error handling for non-numeric message IDs in filenames"""
        mock_tree(mock_ghc.repo, ["test.abc"])  # Non-numeric message ID

        with patch("tgfs.core.repository.impl.metadata.github_repo.Github"):
            repository = GithubRepoMetadataRepository(
                GithubRepoConfig(access_token="test", repo="test/repo", commit="main")
            )
            repository._ghc = mock_ghc

            with patch(
                "tgfs.core.repository.impl.metadata.github_repo.logger"
            ) as mock_logger:
                root_dir = repository._build_directory_structure()

                # Should have no files due to invalid format
                assert len(root_dir.files) == 0

                # Should log warning about invalid format
                mock_logger.warning.assert_called_once()


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_empty_repository(self, mock_ghc):
        """Test handling of completely empty repository"""
        mock_tree(mock_ghc.repo, [])

        with patch("tgfs.core.repository.impl.metadata.github_repo.Github"):
            repository = GithubRepoMetadataRepository(
                GithubRepoConfig(access_token="test", repo="test/repo", commit="main")
            )
            repository._ghc = mock_ghc

            root_dir = repository._build_directory_structure()

            assert root_dir.name == "root"
            assert len(root_dir.files) == 0
            assert len(root_dir.children) == 0

    def test_directory_with_only_gitkeep(self, mock_ghc):
        """Test directory containing only .gitkeep files"""
        mock_tree(
            mock_ghc.repo,
            [".gitkeep", "subdir/", "subdir/.gitkeep"],
        )

        with patch("tgfs.core.repository.impl.metadata.github_repo.Github"):
            repository = GithubRepoMetadataRepository(
                GithubRepoConfig(access_token="test", repo="test/repo", commit="main")
            )
            repository._ghc = mock_ghc

            root_dir = repository._build_directory_structure()

            # Should have subdirectory but no files
            assert len(root_dir.files) == 0
            assert len(root_dir.children) == 1
            assert root_dir.children[0].name == "subdir"
            assert len(root_dir.children[0].files) == 0

    def test_single_content_item_not_in_list(self, mock_ghc):
        """Test handling when get_contents returns single item instead of list"""
        single_file = Mock(spec=ContentFile)
        single_file.name = "single.123"
        single_file.type = "file"
        single_file.path = "single.123"

        # No usable tree, so the walk runs and gets a bare item back
        mock_ghc.repo.get_git_tree.side_effect = Exception("server error")
        mock_ghc.repo.get_contents.return_value = single_file  # Single item, not list

        with patch("tgfs.core.repository.impl.metadata.github_repo.Github"):
            repository = GithubRepoMetadataRepository(
                GithubRepoConfig(access_token="test", repo="test/repo", commit="main")
            )
            repository._ghc = mock_ghc

            root_dir = repository._build_directory_structure()

            # Should handle single item correctly
            assert len(root_dir.files) == 1
            assert root_dir.files[0].name == "single"
            assert root_dir.files[0].message_id == 123
