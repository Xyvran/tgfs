import datetime

import asyncssh
import pytest
from tgfs.app.sftp.server import USER_INFO_KEY, TGFSSFTPServer
from tgfs.auth.user import AdminUser, ReadonlyUser
from tgfs.core import Client
from tgfs.core.model import TGFSDirectory, TGFSFileDesc, TGFSFileVersion

CREATED_AT = datetime.datetime(2024, 1, 1, 12, 0, 0)
UPDATED_AT = datetime.datetime(2024, 6, 1, 12, 0, 0)
FILE_SIZE = 1234


def build_tree() -> TGFSDirectory:
    """root/ with a 'sub' directory and a 'note.txt' file next to it."""
    root = TGFSDirectory.root_dir()
    root.create_dir("sub")
    root.create_file_ref("note.txt", fd_message_id=100)
    return root


def build_file_desc(name: str) -> TGFSFileDesc:
    fd = TGFSFileDesc(name=name, created_at=CREATED_AT)
    fd.add_version(
        TGFSFileVersion(id="v1", updated_at=UPDATED_AT, _size=FILE_SIZE, message_ids=[1])
    )
    return fd


def build_client(mocker, name: str) -> Client:
    root = build_tree()

    client = mocker.Mock(spec=Client)
    client.name = name
    client.dir_api = mocker.Mock()
    client.dir_api.root = root
    client.dir_api.get_fr = mocker.Mock(
        side_effect=lambda directory, file_name: directory.find_file(file_name)
    )
    client.dir_api.create = mocker.AsyncMock(
        side_effect=lambda n, under: under.create_dir(n)
    )
    client.dir_api.rm_empty = mocker.AsyncMock()
    client.dir_api.rm_dangerously = mocker.AsyncMock()
    client.dir_api.move = mocker.AsyncMock()

    client.file_api = mocker.Mock()
    client.file_api.desc = mocker.AsyncMock(
        side_effect=lambda fr: build_file_desc(fr.name)
    )
    client.file_api.rm = mocker.AsyncMock()
    client.file_api.move = mocker.AsyncMock()
    client.file_api.upload = mocker.AsyncMock()

    client.fc_repo = mocker.Mock()
    client.fc_repo.content_length = mocker.AsyncMock(return_value=FILE_SIZE)
    return client


def build_server(mocker, user=None, clients=None) -> TGFSSFTPServer:
    chan = mocker.Mock()
    chan.get_extra_info = mocker.Mock(
        side_effect=lambda key, default=None: (
            user if key == USER_INFO_KEY else default
        )
    )
    config = mocker.Mock()
    config.tgfs.sftp.upload_buffer_size_bytes = 1024
    config.tgfs.sftp.upload_buffer_dir = None

    if clients is None:
        clients = {"notes": build_client(mocker, "notes")}
    return TGFSSFTPServer(chan, clients, config)


def names(entries) -> list:
    return [entry.filename.decode() for entry in entries]


async def collect(async_iterator) -> list:
    return [entry async for entry in async_iterator]


@pytest.fixture
def admin(mocker):
    return build_server(mocker, AdminUser("admin"))


@pytest.fixture
def viewer(mocker):
    return build_server(mocker, ReadonlyUser("viewer"))


class TestRealpath:
    def test_normalizes_without_touching_the_backend(self, admin):
        assert admin.realpath(b"/notes/./sub/../note.txt") == b"/notes/note.txt"

    def test_clamps_escapes_at_the_root(self, admin):
        assert admin.realpath(b"/../..") == b"/"


class TestScandir:
    async def test_root_lists_the_configured_clients(self, mocker):
        clients = {
            "notes": build_client(mocker, "notes"),
            "media": build_client(mocker, "media"),
        }
        server = build_server(mocker, AdminUser("admin"), clients)

        entries = await collect(server.scandir(b"/"))

        assert names(entries) == [".", "..", "notes", "media"]

    async def test_client_root_lists_its_children(self, admin):
        entries = await collect(admin.scandir(b"/notes"))

        assert names(entries) == [".", "..", "sub", "note.txt"]

    async def test_file_entries_carry_their_size(self, admin):
        entries = await collect(admin.scandir(b"/notes"))
        note = next(e for e in entries if e.filename == b"note.txt")

        assert note.attrs.size == FILE_SIZE

    async def test_unknown_client_is_reported_as_missing(self, admin):
        with pytest.raises(asyncssh.SFTPNoSuchFile):
            await collect(admin.scandir(b"/nope"))

    async def test_unknown_directory_is_reported_as_missing(self, admin):
        with pytest.raises(asyncssh.SFTPNoSuchFile):
            await collect(admin.scandir(b"/notes/nope"))

    async def test_unreadable_descriptor_does_not_break_the_listing(
        self, admin, mocker
    ):
        client = admin._clients["notes"]
        client.file_api.desc = mocker.AsyncMock(side_effect=RuntimeError("boom"))

        entries = await collect(admin.scandir(b"/notes"))

        assert names(entries) == [".", "..", "sub", "note.txt"]
        assert next(e for e in entries if e.filename == b"note.txt").attrs.size == 0


class TestStat:
    async def test_root(self, admin):
        attrs = await admin.stat(b"/")

        assert attrs.permissions is not None
        assert attrs.size == 0

    async def test_directory(self, admin):
        attrs = await admin.stat(b"/notes/sub")

        assert attrs.size == 0

    async def test_file(self, admin):
        attrs = await admin.stat(b"/notes/note.txt")

        assert attrs.size == FILE_SIZE
        assert attrs.mtime == int(UPDATED_AT.timestamp())

    async def test_missing_file(self, admin):
        with pytest.raises(asyncssh.SFTPNoSuchFile):
            await admin.stat(b"/notes/nope.txt")

    async def test_lstat_matches_stat(self, admin):
        # There are no symlinks in this filesystem, so the two must agree.
        lstat, stat = (
            await admin.lstat(b"/notes/note.txt"),
            await admin.stat(b"/notes/note.txt"),
        )

        assert (lstat.size, lstat.permissions, lstat.mtime) == (
            stat.size,
            stat.permissions,
            stat.mtime,
        )


class TestReadWrite:
    async def test_open_for_read_returns_a_sized_handle(self, admin):
        handle = await admin.open(b"/notes/note.txt", 0x01, asyncssh.SFTPAttrs())

        assert await admin.fstat(handle) is not None
        assert handle.size == FILE_SIZE

    async def test_open_missing_file_for_read(self, admin):
        with pytest.raises(asyncssh.SFTPNoSuchFile):
            await admin.open(b"/notes/nope.txt", 0x01, asyncssh.SFTPAttrs())

    async def test_open_a_directory_is_refused(self, admin):
        with pytest.raises(asyncssh.SFTPFailure):
            await admin.open(b"/notes/sub", 0x01, asyncssh.SFTPAttrs())

    async def test_open_for_write_reserves_the_name(self, admin):
        handle = await admin.open(
            b"/notes/new.txt", 0x02 | 0x08 | 0x10, asyncssh.SFTPAttrs()
        )

        assert handle.path == "/new.txt"
        admin._clients["notes"].file_api.upload.assert_awaited()

    async def test_exclusive_open_of_an_existing_file_fails(self, admin):
        with pytest.raises(asyncssh.SFTPFailure):
            await admin.open(
                b"/notes/note.txt", 0x02 | 0x08 | 0x20, asyncssh.SFTPAttrs()
            )

    async def test_write_without_create_flag_needs_the_file_to_exist(self, admin):
        with pytest.raises(asyncssh.SFTPNoSuchFile):
            await admin.open(b"/notes/nope.txt", 0x02, asyncssh.SFTPAttrs())

    async def test_append_is_unsupported(self, admin):
        with pytest.raises(asyncssh.SFTPOpUnsupported):
            await admin.open(b"/notes/note.txt", 0x02 | 0x04, asyncssh.SFTPAttrs())

    async def test_reading_a_write_handle_is_refused(self, admin):
        handle = await admin.open(
            b"/notes/new.txt", 0x02 | 0x08, asyncssh.SFTPAttrs()
        )

        with pytest.raises(asyncssh.SFTPFailure):
            await admin.read(handle, 0, 10)

    async def test_writing_a_read_handle_is_refused(self, admin):
        handle = await admin.open(b"/notes/note.txt", 0x01, asyncssh.SFTPAttrs())

        with pytest.raises(asyncssh.SFTPFailure):
            await admin.write(handle, 0, b"nope")


class TestMutations:
    async def test_mkdir(self, admin):
        await admin.mkdir(b"/notes/fresh", asyncssh.SFTPAttrs())

        admin._clients["notes"].dir_api.create.assert_awaited()

    async def test_mkdir_at_the_root_is_refused(self, admin):
        with pytest.raises(asyncssh.SFTPPermissionDenied):
            await admin.mkdir(b"/fresh", asyncssh.SFTPAttrs())

    async def test_rmdir(self, admin):
        await admin.rmdir(b"/notes/sub")

        admin._clients["notes"].dir_api.rm_empty.assert_awaited()

    async def test_rmdir_of_a_client_root_is_refused(self, admin):
        with pytest.raises(asyncssh.SFTPPermissionDenied):
            await admin.rmdir(b"/notes")

    async def test_remove(self, admin):
        await admin.remove(b"/notes/note.txt")

        admin._clients["notes"].file_api.rm.assert_awaited()

    async def test_remove_missing_file(self, admin):
        with pytest.raises(asyncssh.SFTPNoSuchFile):
            await admin.remove(b"/notes/nope.txt")

    async def test_rename_file(self, admin):
        await admin.rename(b"/notes/note.txt", b"/notes/renamed.txt")

        admin._clients["notes"].file_api.move.assert_awaited()

    async def test_rename_directory(self, admin):
        await admin.rename(b"/notes/sub", b"/notes/other")

        admin._clients["notes"].dir_api.move.assert_awaited()

    async def test_posix_rename_behaves_like_rename(self, admin):
        await admin.posix_rename(b"/notes/note.txt", b"/notes/renamed.txt")

        admin._clients["notes"].file_api.move.assert_awaited()

    async def test_rename_across_clients_is_unsupported(self, mocker):
        clients = {
            "notes": build_client(mocker, "notes"),
            "media": build_client(mocker, "media"),
        }
        server = build_server(mocker, AdminUser("admin"), clients)

        with pytest.raises(asyncssh.SFTPOpUnsupported):
            await server.rename(b"/notes/note.txt", b"/media/note.txt")


class TestReadonlyUser:
    async def test_may_list(self, viewer):
        assert names(await collect(viewer.scandir(b"/notes"))) == [
            ".",
            "..",
            "sub",
            "note.txt",
        ]

    async def test_may_read(self, viewer):
        assert await viewer.open(b"/notes/note.txt", 0x01, asyncssh.SFTPAttrs())

    async def test_sees_no_write_permission_bits(self, viewer):
        attrs = await viewer.stat(b"/notes/note.txt")

        assert attrs.permissions is not None
        assert attrs.permissions & 0o222 == 0

    async def test_may_not_open_for_write(self, viewer):
        with pytest.raises(asyncssh.SFTPPermissionDenied):
            await viewer.open(b"/notes/new.txt", 0x02 | 0x08, asyncssh.SFTPAttrs())

    async def test_may_not_mkdir(self, viewer):
        with pytest.raises(asyncssh.SFTPPermissionDenied):
            await viewer.mkdir(b"/notes/fresh", asyncssh.SFTPAttrs())

    async def test_may_not_remove(self, viewer):
        with pytest.raises(asyncssh.SFTPPermissionDenied):
            await viewer.remove(b"/notes/note.txt")

    async def test_may_not_rmdir(self, viewer):
        with pytest.raises(asyncssh.SFTPPermissionDenied):
            await viewer.rmdir(b"/notes/sub")

    async def test_may_not_rename(self, viewer):
        with pytest.raises(asyncssh.SFTPPermissionDenied):
            await viewer.rename(b"/notes/note.txt", b"/notes/other.txt")

    async def test_may_not_setstat(self, viewer):
        with pytest.raises(asyncssh.SFTPPermissionDenied):
            viewer.setstat(b"/notes/note.txt", asyncssh.SFTPAttrs())


class TestUnsupportedOperations:
    def test_readlink(self, admin):
        with pytest.raises(asyncssh.SFTPOpUnsupported):
            admin.readlink(b"/notes/note.txt")

    def test_symlink(self, admin):
        with pytest.raises(asyncssh.SFTPOpUnsupported):
            admin.symlink(b"/notes/note.txt", b"/notes/link.txt")

    def test_link(self, admin):
        with pytest.raises(asyncssh.SFTPOpUnsupported):
            admin.link(b"/notes/note.txt", b"/notes/link.txt")

    def test_statvfs_reports_a_roomy_volume(self, admin):
        attrs = admin.statvfs(b"/")

        assert attrs.bavail > 0
        assert attrs.namemax == 255


class TestExit:
    async def test_aborts_unfinished_uploads(self, admin, mocker):
        handle = await admin.open(
            b"/notes/new.txt", 0x02 | 0x08, asyncssh.SFTPAttrs()
        )
        await handle.write(0, b"partial")
        abort = mocker.spy(handle, "abort")

        await admin.exit()

        abort.assert_called_once()

    async def test_closes_open_reads(self, admin):
        handle = await admin.open(b"/notes/note.txt", 0x01, asyncssh.SFTPAttrs())

        await admin.exit()

        assert admin._handles == []
        assert handle is not None
