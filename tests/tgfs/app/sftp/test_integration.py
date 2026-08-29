"""End-to-end checks driving the server with a real SSH/SFTP client.

These exercise the pieces the unit tests deliberately skip: asyncssh's own
protocol handlers, the handshake, authentication and the handle bookkeeping
between OPEN, READ/WRITE and CLOSE.
"""

import asyncio
import datetime

import asyncssh
import pytest
from tgfs.app.sftp.server import make_server_factory, make_sftp_factory
from tgfs.config import SFTPConfig
from tgfs.core import Client
from tgfs.core.model import TGFSDirectory, TGFSFileDesc, TGFSFileVersion

CONTENT = bytes(range(256)) * 400  # 100 KiB
CREATED_AT = datetime.datetime(2024, 1, 1, 12, 0, 0)
UPDATED_AT = datetime.datetime(2024, 6, 1, 12, 0, 0)


class FakeChannel:
    """A minimal stand-in for the Telegram-backed storage of one client."""

    def __init__(self):
        self.root = TGFSDirectory.root_dir()
        self.contents: dict[str, bytes] = {}

    def add_file(self, directory: TGFSDirectory, name: str, data: bytes) -> None:
        directory.create_file_ref(name, fd_message_id=len(self.contents) + 1)
        self.contents[name] = data


def build_client(mocker, name: str, channel: FakeChannel) -> Client:
    client = mocker.Mock(spec=Client)
    client.name = name

    client.dir_api = mocker.Mock()
    client.dir_api.root = channel.root
    client.dir_api.get_fr = mocker.Mock(
        side_effect=lambda directory, file_name: directory.find_file(file_name)
    )
    client.dir_api.create = mocker.AsyncMock(
        side_effect=lambda n, under: under.create_dir(n)
    )
    client.dir_api.rm_empty = mocker.AsyncMock(
        side_effect=lambda d: d.parent.children.remove(d)
    )
    client.dir_api.rm_dangerously = mocker.AsyncMock()
    client.dir_api.move = mocker.AsyncMock()

    def desc(fr):
        fd = TGFSFileDesc(name=fr.name, created_at=CREATED_AT)
        fd.add_version(
            TGFSFileVersion(
                id="v1",
                updated_at=UPDATED_AT,
                _size=len(channel.contents.get(fr.name, b"")),
                message_ids=[fr.message_id],
            )
        )
        return fd

    async def retrieve(fr, begin, end, as_name):
        data = channel.contents.get(fr.name, b"")
        stop = len(data) if end < 0 else min(len(data), end + 1)

        async def stream():
            for start in range(begin, stop, 8192):
                yield data[start : min(start + 8192, stop)]

        return stream()

    async def upload(directory, file_msg):
        # `touch` sends a FileMessageEmpty, which carries no readable body.
        size = file_msg.size or 0
        data = await file_msg.read(size) if size > 0 else b""
        if not directory.find_files([file_msg.name]):
            channel.add_file(directory, file_msg.name, data)
        else:
            channel.contents[file_msg.name] = data
        return desc(directory.find_file(file_msg.name))

    async def rm(fr):
        fr.delete()
        channel.contents.pop(fr.name, None)

    client.file_api = mocker.Mock()
    client.file_api.desc = mocker.AsyncMock(side_effect=desc)
    client.file_api.retrieve = mocker.AsyncMock(side_effect=retrieve)
    client.file_api.upload = mocker.AsyncMock(side_effect=upload)
    client.file_api.rm = mocker.AsyncMock(side_effect=rm)
    client.file_api.move = mocker.AsyncMock()

    client.fc_repo = mocker.Mock()
    client.fc_repo.content_length = mocker.AsyncMock(side_effect=lambda fv: fv.size)
    return client


def build_config(mocker, users):
    config = mocker.Mock()
    config.tgfs.users = users
    config.tgfs.sftp = SFTPConfig.from_dict({"upload_buffer_size_mb": 0})
    return config


@pytest.fixture
def channel():
    channel = FakeChannel()
    channel.add_file(channel.root, "note.txt", CONTENT)
    channel.root.create_dir("sub")
    return channel


@pytest.fixture
def users(mocker):
    return {
        "admin": mocker.Mock(password="secret", readonly=False),
        "viewer": mocker.Mock(password="secret", readonly=True),
    }


@pytest.fixture
async def server(mocker, channel, users):
    mocker.patch("tgfs.core.ops.create_upload_task", new_callable=mocker.AsyncMock)
    mocker.patch(
        "tgfs.app.sftp.server.authenticate",
        side_effect=lambda username, password: _authenticate(users, username, password),
    )

    clients = {"notes": build_client(mocker, "notes", channel)}
    config = build_config(mocker, users)

    acceptor = await asyncssh.listen(
        host="127.0.0.1",
        port=0,
        server_factory=make_server_factory(config),
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        sftp_factory=make_sftp_factory(clients, config),
    )
    try:
        yield acceptor
    finally:
        acceptor.close()
        await acceptor.wait_closed()


def _authenticate(users, username, password):
    from tgfs.auth.user import AdminUser, ReadonlyUser
    from tgfs.errors.tgfs import LoginFailed

    user = users.get(username)
    if user is None or user.password != password:
        raise LoginFailed("No such user or password is incorrect.")
    return ReadonlyUser(username) if user.readonly else AdminUser(username)


async def connect(acceptor, username="admin", password="secret"):
    return await asyncssh.connect(
        host="127.0.0.1",
        port=acceptor.get_port(),
        username=username,
        password=password,
        known_hosts=None,
    )


class TestAuthentication:
    async def test_valid_credentials_are_accepted(self, server):
        async with await connect(server) as conn:
            async with conn.start_sftp_client() as sftp:
                assert await sftp.listdir("/") == [".", "..", "notes"]

    async def test_a_wrong_password_is_rejected(self, server):
        with pytest.raises(asyncssh.PermissionDenied):
            await connect(server, password="wrong")

    async def test_an_unknown_user_is_rejected(self, server):
        with pytest.raises(asyncssh.PermissionDenied):
            await connect(server, username="ghost")


class TestBrowsing:
    async def test_root_lists_the_clients(self, server):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            assert await sftp.listdir("/") == [".", "..", "notes"]

    async def test_client_root_lists_its_entries(self, server):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            assert sorted(await sftp.listdir("/notes")) == [
                ".",
                "..",
                "note.txt",
                "sub",
            ]

    async def test_stat_reports_the_file_size(self, server):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            assert (await sftp.stat("/notes/note.txt")).size == len(CONTENT)

    async def test_isdir_and_isfile(self, server):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            assert await sftp.isdir("/notes/sub")
            assert await sftp.isfile("/notes/note.txt")

    async def test_missing_paths_are_reported(self, server):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            with pytest.raises(asyncssh.SFTPNoSuchFile):
                await sftp.stat("/notes/nope.txt")


class TestTransfers:
    async def test_download_returns_the_whole_file(self, server, tmp_path):
        target = tmp_path / "note.txt"
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            await sftp.get("/notes/note.txt", str(target))

        assert target.read_bytes() == CONTENT

    async def test_random_access_read(self, server):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            async with await sftp.open("/notes/note.txt", "rb") as fh:
                await fh.seek(70_000)
                tail = await fh.read(64)
                await fh.seek(10)
                head = await fh.read(64)

        assert tail == CONTENT[70_000:70_064]
        assert head == CONTENT[10:74]

    async def test_upload_stores_the_payload(self, server, channel, tmp_path):
        source = tmp_path / "upload.bin"
        payload = bytes(range(256)) * 200
        source.write_bytes(payload)

        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            await sftp.put(str(source), "/notes/upload.bin")

        assert channel.contents["upload.bin"] == payload

    async def test_round_trip(self, server, tmp_path):
        source = tmp_path / "round.bin"
        target = tmp_path / "round.out"
        source.write_bytes(CONTENT)

        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            await sftp.put(str(source), "/notes/round.bin")
            await sftp.get("/notes/round.bin", str(target))

        assert target.read_bytes() == CONTENT

    async def test_an_empty_upload_creates_an_empty_file(self, server, channel, tmp_path):
        source = tmp_path / "empty.bin"
        source.write_bytes(b"")

        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            await sftp.put(str(source), "/notes/empty.bin")

        assert channel.contents["empty.bin"] == b""


class TestMutations:
    async def test_mkdir_and_rmdir(self, server, channel):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            await sftp.mkdir("/notes/fresh")
            assert "fresh" in [d.name for d in channel.root.find_dirs()]

            await sftp.rmdir("/notes/fresh")
            assert "fresh" not in [d.name for d in channel.root.find_dirs()]

    async def test_remove(self, server, channel):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            await sftp.remove("/notes/note.txt")

        assert channel.root.find_files(["note.txt"]) == []

    async def test_mkdir_at_the_root_is_refused(self, server):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            with pytest.raises(asyncssh.SFTPPermissionDenied):
                await sftp.mkdir("/fresh")


class TestReadonlyUser:
    async def test_may_read(self, server, tmp_path):
        target = tmp_path / "note.txt"
        async with await connect(server, username="viewer") as conn:
            async with conn.start_sftp_client() as sftp:
                await sftp.get("/notes/note.txt", str(target))

        assert target.read_bytes() == CONTENT

    async def test_may_not_upload(self, server, tmp_path):
        source = tmp_path / "upload.bin"
        source.write_bytes(b"nope")

        async with await connect(server, username="viewer") as conn:
            async with conn.start_sftp_client() as sftp:
                with pytest.raises(asyncssh.SFTPPermissionDenied):
                    await sftp.put(str(source), "/notes/upload.bin")

    async def test_may_not_remove(self, server):
        async with await connect(server, username="viewer") as conn:
            async with conn.start_sftp_client() as sftp:
                with pytest.raises(asyncssh.SFTPPermissionDenied):
                    await sftp.remove("/notes/note.txt")


class TestConcurrency:
    async def test_parallel_reads_of_the_same_file(self, server):
        async with await connect(server) as conn, conn.start_sftp_client() as sftp:
            async with await sftp.open("/notes/note.txt", "rb") as fh:
                chunks = await asyncio.gather(
                    *(fh.read(1024, offset) for offset in range(0, 8192, 1024))
                )

        assert b"".join(chunks) == CONTENT[:8192]
