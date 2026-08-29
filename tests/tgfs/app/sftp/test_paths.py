import pytest
from tgfs.app.sftp.paths import ResolvedPath, normalize, resolve


class TestNormalize:
    @pytest.mark.parametrize(
        "given,expected",
        [
            (b"/", "/"),
            (b"", "/"),
            (b".", "/"),
            (b"notes", "/notes"),
            (b"/notes/", "/notes"),
            (b"/notes//sub///file.txt", "/notes/sub/file.txt"),
            (b"/notes/./sub/../file.txt", "/notes/file.txt"),
            (b"notes\\sub", "/notes/sub"),
        ],
    )
    def test_normalizes(self, given, expected):
        assert normalize(given) == expected

    @pytest.mark.parametrize(
        "given,expected",
        [
            (b"/..", "/"),
            (b"/../../etc/passwd", "/etc/passwd"),
            (b"../..", "/"),
            (b"/notes/../../..", "/"),
        ],
    )
    def test_clamps_escapes_at_the_root(self, given, expected):
        assert normalize(given) == expected

    def test_accepts_str(self):
        assert normalize("/notes/sub") == "/notes/sub"

    def test_keeps_non_utf8_bytes_addressable(self):
        assert normalize(b"/notes/\xff") == "/notes/\udcff"


class TestResolve:
    def test_root(self):
        resolved = resolve(b"/")

        assert resolved == ResolvedPath(client_name="", relative="/")
        assert resolved.is_root
        assert not resolved.is_client_root
        assert resolved.basename == "/"
        assert resolved.as_global() == "/"

    def test_client_root(self):
        resolved = resolve(b"/notes")

        assert resolved == ResolvedPath(client_name="notes", relative="/")
        assert not resolved.is_root
        assert resolved.is_client_root
        assert resolved.basename == "notes"
        assert resolved.as_global() == "/notes"

    def test_client_root_with_trailing_slash(self):
        assert resolve(b"/notes/") == ResolvedPath(client_name="notes", relative="/")

    def test_nested(self):
        resolved = resolve(b"/notes/sub/file.txt")

        assert resolved == ResolvedPath(
            client_name="notes", relative="/sub/file.txt"
        )
        assert resolved.basename == "file.txt"
        assert resolved.as_global() == "/notes/sub/file.txt"

    def test_escape_lands_on_the_root(self):
        assert resolve(b"/notes/../..").is_root


class TestChild:
    def test_child_of_root_is_a_client_root(self):
        assert resolve(b"/").child("notes") == ResolvedPath(
            client_name="notes", relative="/"
        )

    def test_child_of_client_root(self):
        assert resolve(b"/notes").child("file.txt") == ResolvedPath(
            client_name="notes", relative="/file.txt"
        )

    def test_child_of_nested_directory(self):
        assert resolve(b"/notes/sub").child("file.txt") == ResolvedPath(
            client_name="notes", relative="/sub/file.txt"
        )
