import pytest

from tgfs.app.utils import split_global_path, strip_webdav_prefix


class TestStripWebdavPrefix:
    def test_strips_the_mount_point_and_client_name(self):
        assert (
            strip_webdav_prefix("/webdav/notes-1/dest/file.txt", "notes-1")
            == "/dest/file.txt"
        )

    def test_handles_the_client_root(self):
        assert strip_webdav_prefix("/webdav/notes-1", "notes-1") == ""

    def test_leaves_an_already_relative_path_alone(self):
        assert strip_webdav_prefix("/dest/file.txt", "notes-1") == "/dest/file.txt"

    def test_only_strips_on_a_path_boundary(self):
        # A client called "notes" must not swallow the "-1" of "notes-1".
        assert (
            strip_webdav_prefix("/webdav/notes-1/file.txt", "notes")
            == "/webdav/notes-1/file.txt"
        )


class TestSplitGlobalPath:
    @pytest.mark.parametrize(
        "path,expected",
        [
            ("notes-1/test/test.txt", ("notes-1", "test/test.txt")),
            ("/notes-1/test/test.txt", ("notes-1", "test/test.txt")),
            ("notes-1", ("notes-1", "")),
        ],
    )
    def test_splits_off_the_client_name(self, path, expected):
        assert split_global_path(path) == expected
