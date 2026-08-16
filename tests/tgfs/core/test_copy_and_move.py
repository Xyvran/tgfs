"""End-to-end behaviour of copying and moving, against a fake channel.

Two regressions are pinned down here.

*Moving* used to be a copy followed by a removal. Because a copy only created
a second reference to the *same* telegram messages, the removal then deleted
the descriptor and content messages the moved file was still pointing at: the
file stayed listed but reported 0 bytes and downloaded as empty. A move is now
a pure metadata relocation.

*Copying* used to share the descriptor with the original, so writing to the
copy rewrote the original as well -- and copying a directory handed over the
source's own children/files lists, making the two indistinguishable. A copy
now duplicates the content messages server-side (no bytes on the wire) and
gets its own descriptor.

The tests drive the real ``Ops`` / ``FileApi`` / ``TGMsgFDRepository`` stack
with message deletion switched on -- the setting under which the data loss
happened.
"""

from typing import Dict, List, Optional, cast

import pytest

from tgfs.core.api.directory import DirectoryApi
from tgfs.core.api.file import FileApi
from tgfs.core.api.file_desc import FileDescApi
from tgfs.core.api.message import MessageApi
from tgfs.core.api.metadata import MetaDataApi
from tgfs.core.client import Client
from tgfs.core.model import TGFSDirectory, TGFSMetadata
from tgfs.core.ops import Ops
from tgfs.core.repository.impl.fd.tg_msg import TGMsgFDRepository
from tgfs.core.repository.interface import IFileContentRepository, IMetaDataRepository
from tgfs.errors import InvalidPath
from tgfs.reqres import Document, MessageResp, SentFileMessage


class FakeChannel:
    """The handful of telegram behaviours the stack under test relies on."""

    def __init__(self) -> None:
        self.messages: Dict[int, MessageResp] = {}
        self._next_id = 100

    def _take_id(self) -> int:
        message_id, self._next_id = self._next_id, self._next_id + 1
        return message_id

    def send_text(self, text: str) -> int:
        message_id = self._take_id()
        self.messages[message_id] = MessageResp(
            message_id=message_id, text=text, document=None
        )
        return message_id

    def send_document(self, size: int) -> int:
        message_id = self._take_id()
        self.messages[message_id] = MessageResp(
            message_id=message_id,
            text="",
            document=Document(
                size=size,
                id=message_id,
                access_hash=0,
                file_reference=b"",
                mime_type="application/octet-stream",
            ),
        )
        return message_id


class FakeMessageApi:
    def __init__(self, channel: FakeChannel) -> None:
        self.channel = channel
        self.duplicated: List[int] = []

    async def send_text(self, message: str) -> int:
        return self.channel.send_text(message)

    async def edit_message_text(self, message_id: int, message: str) -> int:
        self.channel.messages[message_id] = MessageResp(
            message_id=message_id, text=message, document=None
        )
        return message_id

    async def get_messages(self, ids: List[int]) -> List[Optional[MessageResp]]:
        return [self.channel.messages.get(message_id) for message_id in ids]

    async def duplicate_messages(self, ids: List[int]) -> List[int]:
        # Forwarding is server-side: new message ids pointing at documents
        # that are already on telegram. The fake mimics that by cloning the
        # entry -- no payload changes hands, exactly as in the real thing.
        self.duplicated.extend(ids)
        new_ids = []
        for message_id in ids:
            message = self.channel.messages[message_id]
            assert message.document is not None
            new_ids.append(self.channel.send_document(message.document.size))
        return new_ids

    async def delete_messages(self, ids, force: bool = False) -> None:
        # Stands in for a deployment with telegram.delete_messages_on_remove
        # turned on.
        for message_id in ids:
            self.channel.messages.pop(message_id, None)


class FakeFileContentRepository(IFileContentRepository):
    def __init__(self, channel: FakeChannel) -> None:
        self.channel = channel
        self.uploads = 0

    async def save(self, file_msg) -> List[SentFileMessage]:
        self.uploads += 1
        size = file_msg.get_size()
        return [SentFileMessage(self.channel.send_document(size), size)]

    async def get(self, fv, begin, end, name):
        raise NotImplementedError

    async def update(self, message_id: int, buffer: bytes, name: str) -> int:
        return message_id


class FakeMetadataRepository(IMetaDataRepository):
    def __init__(self) -> None:
        super().__init__()
        self.metadata = TGFSMetadata(dir=TGFSDirectory.root_dir())
        self.pushes = 0

    async def push(self) -> None:
        self.pushes += 1

    async def get(self) -> TGFSMetadata:
        assert self.metadata is not None
        return self.metadata


class FakeClient:
    def __init__(self) -> None:
        self.name = "test"
        self.channel = FakeChannel()
        self.fake_message_api = FakeMessageApi(self.channel)
        message_api = cast(MessageApi, self.fake_message_api)
        self.fc_repo = FakeFileContentRepository(self.channel)
        file_desc_api = FileDescApi(TGMsgFDRepository(message_api), self.fc_repo)
        self.metadata_repo = FakeMetadataRepository()
        self.metadata_api = MetaDataApi(self.metadata_repo)
        self.file_api = FileApi(self.metadata_api, file_desc_api, message_api)
        self.dir_api = DirectoryApi(self.metadata_api, self.file_api, message_api)


@pytest.fixture
def client() -> FakeClient:
    fake = FakeClient()
    root = fake.dir_api.root
    root.create_dir("src")
    root.create_dir("dest")
    return fake


@pytest.fixture
def ops(client) -> Ops:
    return Ops(cast(Client, client))


async def size_of(ops: Ops, path: str) -> int:
    fd = await ops.desc(path)
    return fd.get_latest_version().size


class TestMove:
    @pytest.mark.asyncio
    async def test_moving_a_file_keeps_its_size(self, ops):
        await ops.upload_from_bytes(b"x" * 1234, "/src/file.txt")
        assert await size_of(ops, "/src/file.txt") == 1234

        await ops.mv_file("/src/file.txt", "/dest/file.txt")

        assert await size_of(ops, "/dest/file.txt") == 1234

    @pytest.mark.asyncio
    async def test_moving_a_directory_keeps_the_sizes_below_it(self, ops):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 999, "/src/sub/file.txt")

        await ops.mv_dir("/src/sub", "/dest/sub")

        assert await size_of(ops, "/dest/sub/file.txt") == 999

    @pytest.mark.asyncio
    async def test_moving_touches_neither_content_nor_descriptor(self, ops, client):
        await ops.upload_from_bytes(b"x" * 12, "/src/file.txt")
        before = dict(client.channel.messages)

        await ops.mv_file("/src/file.txt", "/dest/file.txt")

        assert client.channel.messages == before
        assert client.fake_message_api.duplicated == []

    @pytest.mark.asyncio
    async def test_removing_the_last_reference_still_deletes_the_messages(self, ops):
        await ops.upload_from_bytes(b"x" * 77, "/src/file.txt")
        await ops.mv_file("/src/file.txt", "/dest/file.txt")

        await ops.rm_file("/dest/file.txt")

        assert cast(FakeClient, ops._client).channel.messages == {}


class TestCopyFile:
    @pytest.mark.asyncio
    async def test_copy_duplicates_without_uploading(self, ops, client):
        await ops.upload_from_bytes(b"x" * 4321, "/src/file.txt")
        uploads_after_creation = client.fc_repo.uploads

        await ops.cp_file("/src/file.txt", "/dest/file.txt")

        assert await size_of(ops, "/dest/file.txt") == 4321
        # The content message was forwarded, not re-uploaded.
        assert client.fc_repo.uploads == uploads_after_creation
        assert len(client.fake_message_api.duplicated) == 1

    @pytest.mark.asyncio
    async def test_the_copy_has_its_own_descriptor_and_parts(self, ops):
        await ops.upload_from_bytes(b"x" * 10, "/src/file.txt")

        await ops.cp_file("/src/file.txt", "/dest/file.txt")

        original = ops.stat_file("/src/file.txt")
        copy = ops.stat_file("/dest/file.txt")
        assert original.message_id != copy.message_id
        original_fd = await ops.desc("/src/file.txt")
        copied_fd = await ops.desc("/dest/file.txt")
        assert not set(original_fd.get_latest_version().message_ids) & set(
            copied_fd.get_latest_version().message_ids
        )

    @pytest.mark.asyncio
    async def test_overwriting_the_copy_leaves_the_original_alone(self, ops):
        await ops.upload_from_bytes(b"x" * 100, "/src/file.txt")
        await ops.cp_file("/src/file.txt", "/dest/file.txt")

        await ops.upload_from_bytes(b"y" * 5, "/dest/file.txt")

        assert await size_of(ops, "/dest/file.txt") == 5
        assert await size_of(ops, "/src/file.txt") == 100

    @pytest.mark.asyncio
    async def test_overwriting_the_original_leaves_the_copy_alone(self, ops):
        await ops.upload_from_bytes(b"x" * 100, "/src/file.txt")
        await ops.cp_file("/src/file.txt", "/dest/file.txt")

        await ops.upload_from_bytes(b"y" * 5, "/src/file.txt")

        assert await size_of(ops, "/src/file.txt") == 5
        assert await size_of(ops, "/dest/file.txt") == 100

    @pytest.mark.asyncio
    async def test_removing_the_original_keeps_the_copy_readable(self, ops):
        await ops.upload_from_bytes(b"x" * 4321, "/src/file.txt")
        await ops.cp_file("/src/file.txt", "/dest/file.txt")

        await ops.rm_file("/src/file.txt")

        assert await size_of(ops, "/dest/file.txt") == 4321

    @pytest.mark.asyncio
    async def test_removing_the_copy_keeps_the_original_readable(self, ops):
        await ops.upload_from_bytes(b"x" * 4321, "/src/file.txt")
        await ops.cp_file("/src/file.txt", "/dest/file.txt")

        await ops.rm_file("/dest/file.txt")

        assert await size_of(ops, "/src/file.txt") == 4321

    @pytest.mark.asyncio
    async def test_copy_carries_the_full_version_history(self, ops, client):
        await ops.upload_from_bytes(b"x" * 100, "/src/file.txt")
        await ops.upload_from_bytes(b"y" * 200, "/src/file.txt")
        await ops.upload_from_bytes(b"z" * 300, "/src/file.txt")

        await ops.cp_file("/src/file.txt", "/dest/file.txt")

        original = await client.file_api.desc(
            ops.stat_file("/src/file.txt"), include_all_versions=True
        )
        copy = await client.file_api.desc(
            ops.stat_file("/dest/file.txt"), include_all_versions=True
        )
        assert sorted(v.size for v in copy.get_versions()) == [100, 200, 300]
        assert sorted(v.updated_at for v in copy.get_versions()) == sorted(
            v.updated_at for v in original.get_versions()
        )
        assert copy.get_latest_version().size == original.get_latest_version().size
        # Independent files must not share version ids either.
        assert not set(copy.versions) & set(original.versions)
        # Every part of every version was duplicated in one batched call.
        assert len(client.fake_message_api.duplicated) == 3

    @pytest.mark.asyncio
    async def test_copying_an_empty_file_duplicates_nothing(self, ops, client):
        await ops.touch("/src/empty.txt")

        await ops.cp_file("/src/empty.txt", "/dest/empty.txt")

        assert client.fake_message_api.duplicated == []
        assert ops.stat_file("/dest/empty.txt").message_id != ops.stat_file(
            "/src/empty.txt"
        ).message_id


class TestCopyDir:
    @pytest.mark.asyncio
    async def test_copy_dir_is_recursive_and_independent(self, ops, client):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 11, "/src/top.txt")
        await ops.upload_from_bytes(b"x" * 22, "/src/sub/inner.txt")
        uploads = client.fc_repo.uploads

        await ops.cp_dir("/src", "/dest/copy")

        assert await size_of(ops, "/dest/copy/top.txt") == 11
        assert await size_of(ops, "/dest/copy/sub/inner.txt") == 22
        assert client.fc_repo.uploads == uploads

        # Adding to the copy must not show up in the source, and the file
        # refs of the copy must belong to the copy's own directories.
        await ops.upload_from_bytes(b"x" * 33, "/dest/copy/extra.txt")
        assert [f.name for f in ops.cd("/src").find_files()] == ["top.txt"]
        assert ops.cd("/dest/copy").find_file("top.txt").location is ops.cd(
            "/dest/copy"
        )

    @pytest.mark.asyncio
    async def test_removing_the_copied_dir_keeps_the_source(self, ops):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 22, "/src/sub/inner.txt")
        await ops.cp_dir("/src/sub", "/dest/sub")

        await ops.rm_dir("/dest/sub", True)

        assert await size_of(ops, "/src/sub/inner.txt") == 22

    @pytest.mark.asyncio
    async def test_removing_the_source_dir_keeps_the_copy(self, ops):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 22, "/src/sub/inner.txt")
        await ops.cp_dir("/src/sub", "/dest/sub")

        await ops.rm_dir("/src/sub", True)

        assert await size_of(ops, "/dest/sub/inner.txt") == 22

    @pytest.mark.asyncio
    async def test_copy_dir_writes_the_metadata_once(self, ops, client):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 11, "/src/top.txt")
        await ops.upload_from_bytes(b"x" * 22, "/src/sub/inner.txt")
        pushes = client.metadata_repo.pushes

        await ops.cp_dir("/src", "/dest/copy")

        assert client.metadata_repo.pushes == pushes + 1

    @pytest.mark.asyncio
    async def test_copy_dir_refuses_to_descend_into_itself(self, ops):
        await ops.mkdir("/src/sub", False)

        with pytest.raises(InvalidPath):
            await ops.cp_dir("/src", "/src/sub/copy")
