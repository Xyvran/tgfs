"""SFTP renames against the real ``Ops`` / ``FileApi`` stack.

``posix_rename`` used to behave exactly like ``rename`` and refuse an
existing target, although posix-rename@openssh.com (and RENAME with
FXR_OVERWRITE) promises rename(2) semantics. sshfs, rclone and editors save
by renaming a temporary file over the original, so those saves failed.
"""

from typing import cast

import asyncssh
import pytest

from tgfs.app.sftp.server import (
    USER_INFO_KEY,
    TGFSSFTPServer,
    make_server_factory,
    make_sftp_factory,
)
from tgfs.auth.user import AdminUser
from tgfs.config import SFTPConfig
from tgfs.core import Client
from tgfs.core.ops import Ops
from tests.tgfs.core.test_copy_and_move import FakeClient


@pytest.fixture
def client() -> FakeClient:
    fake = FakeClient()
    fake.name = "notes"
    root = fake.dir_api.root
    root.create_dir("src")
    root.create_dir("dest")
    return fake


@pytest.fixture
def ops(client) -> Ops:
    return Ops(cast(Client, client))


@pytest.fixture
def config(mocker):
    config = mocker.Mock()
    config.tgfs.users = {"admin": mocker.Mock(password="secret", readonly=False)}
    config.tgfs.sftp = SFTPConfig.from_dict({"upload_buffer_size_mb": 0})
    return config


@pytest.fixture
def server(mocker, client, config) -> TGFSSFTPServer:
    chan = mocker.Mock()
    chan.get_extra_info = mocker.Mock(
        side_effect=lambda key, default=None: (
            AdminUser("admin") if key == USER_INFO_KEY else default
        )
    )
    return TGFSSFTPServer(chan, {"notes": cast(Client, client)}, config)


async def size_of(ops: Ops, path: str) -> int:
    fd = await ops.desc(path)
    return fd.get_latest_version().size


def file_names(ops: Ops, path: str) -> list:
    return sorted(f.name for f in ops.cd(path).find_files())


class TestRename:
    async def test_renames_a_file(self, server, ops):
        await ops.upload_from_bytes(b"x" * 12, "/src/a.txt")

        await server.rename(b"/notes/src/a.txt", b"/notes/src/b.txt")

        assert file_names(ops, "/src") == ["b.txt"]
        assert await size_of(ops, "/src/b.txt") == 12

    async def test_renames_a_directory(self, server, ops):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 4, "/src/sub/a.txt")

        await server.rename(b"/notes/src/sub", b"/notes/dest/moved")

        assert await size_of(ops, "/dest/moved/a.txt") == 4
        assert ops.cd("/src").find_dirs() == []

    async def test_refuses_an_existing_target(self, server, ops):
        await ops.upload_from_bytes(b"n" * 10, "/src/a.txt")
        await ops.upload_from_bytes(b"o" * 20, "/dest/a.txt")

        with pytest.raises(asyncssh.SFTPFileAlreadyExists):
            await server.rename(b"/notes/src/a.txt", b"/notes/dest/a.txt")

        assert await size_of(ops, "/src/a.txt") == 10
        assert await size_of(ops, "/dest/a.txt") == 20

    async def test_onto_itself_is_a_no_op(self, server, ops):
        await ops.upload_from_bytes(b"x" * 3, "/src/a.txt")

        await server.rename(b"/notes/src/a.txt", b"/notes/src/a.txt")

        assert await size_of(ops, "/src/a.txt") == 3

    async def test_a_missing_source_is_reported(self, server):
        with pytest.raises(asyncssh.SFTPNoSuchFile):
            await server.rename(b"/notes/src/none.txt", b"/notes/src/b.txt")

    async def test_a_directory_cannot_move_into_itself(self, server, ops):
        await ops.mkdir("/src/sub", False)

        with pytest.raises(asyncssh.SFTPFailure):
            await server.rename(b"/notes/src", b"/notes/src/sub/src")

        ops.cd("/src/sub")


class TestPosixRename:
    async def test_replaces_an_existing_file(self, server, ops, client):
        await ops.upload_from_bytes(b"n" * 10, "/src/a.txt")
        await ops.upload_from_bytes(b"o" * 20, "/dest/a.txt")
        replaced = ops.stat_file("/dest/a.txt").message_id

        await server.posix_rename(b"/notes/src/a.txt", b"/notes/dest/a.txt")

        assert file_names(ops, "/src") == []
        assert file_names(ops, "/dest") == ["a.txt"]
        assert await size_of(ops, "/dest/a.txt") == 10
        assert replaced not in client.channel.messages

    async def test_replaces_an_empty_directory(self, server, ops):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 5, "/src/sub/a.txt")
        await ops.mkdir("/dest/sub", False)

        await server.posix_rename(b"/notes/src/sub", b"/notes/dest/sub")

        assert await size_of(ops, "/dest/sub/a.txt") == 5
        assert ops.cd("/src").find_dirs() == []

    async def test_never_replaces_a_non_empty_directory(self, server, ops):
        await ops.mkdir("/src/sub", False)
        await ops.mkdir("/dest/sub", False)
        await ops.upload_from_bytes(b"x" * 5, "/dest/sub/keep.txt")

        with pytest.raises(asyncssh.SFTPDirNotEmpty):
            await server.posix_rename(b"/notes/src/sub", b"/notes/dest/sub")

        assert file_names(ops, "/dest/sub") == ["keep.txt"]
        ops.cd("/src/sub")

    async def test_a_file_does_not_replace_a_directory(self, server, ops):
        await ops.upload_from_bytes(b"x", "/src/a")
        await ops.mkdir("/dest/a", False)

        with pytest.raises(asyncssh.SFTPFileIsADirectory):
            await server.posix_rename(b"/notes/src/a", b"/notes/dest/a")

        ops.cd("/dest/a")
        ops.stat_file("/src/a")

    async def test_a_directory_does_not_replace_a_file(self, server, ops):
        await ops.mkdir("/src/a", False)
        await ops.upload_from_bytes(b"x", "/dest/a")

        with pytest.raises(asyncssh.SFTPNotADirectory):
            await server.posix_rename(b"/notes/src/a", b"/notes/dest/a")

        ops.stat_file("/dest/a")
        ops.cd("/src/a")

    async def test_does_not_replace_a_parent_of_the_source(self, server, ops):
        await ops.mkdir("/src/sub", False)

        with pytest.raises(asyncssh.SFTPDirNotEmpty):
            await server.posix_rename(b"/notes/src/sub", b"/notes/src")

        ops.cd("/src/sub")

    async def test_a_missing_target_folder_is_reported(self, server, ops):
        await ops.upload_from_bytes(b"x", "/src/a.txt")

        with pytest.raises(asyncssh.SFTPNoSuchFile):
            await server.posix_rename(b"/notes/src/a.txt", b"/notes/nope/a.txt")

        ops.stat_file("/src/a.txt")


class TestOverTheWire:
    """The same through a real SSH connection, so asyncssh's own routing of
    RENAME and posix-rename@openssh.com to the two methods is covered too."""

    @pytest.fixture
    async def sftp(self, mocker, client, config):
        mocker.patch(
            "tgfs.app.sftp.server.authenticate",
            side_effect=lambda username, password: AdminUser(username),
        )
        acceptor = await asyncssh.listen(
            host="127.0.0.1",
            port=0,
            server_factory=make_server_factory(config),
            server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
            sftp_factory=make_sftp_factory({"notes": cast(Client, client)}, config),
        )
        try:
            async with await asyncssh.connect(
                host="127.0.0.1",
                port=acceptor.get_port(),
                username="admin",
                password="secret",
                known_hosts=None,
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    yield sftp
        finally:
            acceptor.close()
            await acceptor.wait_closed()

    async def test_rename_refuses_an_existing_target(self, sftp, ops):
        await ops.upload_from_bytes(b"n" * 10, "/src/a.txt")
        await ops.upload_from_bytes(b"o" * 20, "/dest/a.txt")

        with pytest.raises(asyncssh.SFTPFailure):
            await sftp.rename("/notes/src/a.txt", "/notes/dest/a.txt")

        assert await size_of(ops, "/dest/a.txt") == 20

    async def test_posix_rename_replaces_an_existing_target(self, sftp, ops):
        await ops.upload_from_bytes(b"n" * 10, "/src/a.txt")
        await ops.upload_from_bytes(b"o" * 20, "/dest/a.txt")

        await sftp.posix_rename("/notes/src/a.txt", "/notes/dest/a.txt")

        assert file_names(ops, "/dest") == ["a.txt"]
        assert await size_of(ops, "/dest/a.txt") == 10
