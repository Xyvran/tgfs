"""Regression tests for the file size disappearing after a WebDAV move.

A move used to be a copy followed by a removal. Because a copy only creates a
second reference to the *same* telegram messages, the removal then deleted the
descriptor and content messages the moved file was still pointing at: the file
stayed listed but reported 0 bytes and downloaded as empty.

These tests drive the real ``Ops`` / ``FileApi`` / ``TGMsgFDRepository`` stack
against an in-memory channel, with message deletion switched on -- the setting
under which the data loss happened.
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

    async def send_text(self, message: str) -> int:
        return self.channel.send_text(message)

    async def edit_message_text(self, message_id: int, message: str) -> int:
        self.channel.messages[message_id] = MessageResp(
            message_id=message_id, text=message, document=None
        )
        return message_id

    async def get_messages(self, ids: List[int]) -> List[Optional[MessageResp]]:
        return [self.channel.messages.get(message_id) for message_id in ids]

    async def delete_messages(self, ids, force: bool = False) -> None:
        # Stands in for a deployment with telegram.delete_messages_on_remove
        # turned on.
        for message_id in ids:
            self.channel.messages.pop(message_id, None)


class FakeFileContentRepository(IFileContentRepository):
    def __init__(self, channel: FakeChannel) -> None:
        self.channel = channel

    async def save(self, file_msg) -> List[SentFileMessage]:
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

    async def push(self) -> None:
        pass

    async def get(self) -> TGFSMetadata:
        assert self.metadata is not None
        return self.metadata


class FakeClient:
    def __init__(self) -> None:
        self.name = "test"
        self.channel = FakeChannel()
        message_api = cast(MessageApi, FakeMessageApi(self.channel))
        self.fc_repo = FakeFileContentRepository(self.channel)
        file_desc_api = FileDescApi(TGMsgFDRepository(message_api), self.fc_repo)
        self.metadata_api = MetaDataApi(FakeMetadataRepository())
        self.file_api = FileApi(self.metadata_api, file_desc_api, message_api)
        self.dir_api = DirectoryApi(self.metadata_api, self.file_api, message_api)


@pytest.fixture
def ops() -> Ops:
    client = FakeClient()
    root = client.dir_api.root
    root.create_dir("src", None)
    root.create_dir("dest", None)
    return Ops(cast(Client, client))


async def size_of(ops: Ops, path: str) -> int:
    fd = await ops.desc(path)
    return fd.get_latest_version().size


class TestMoveKeepsFileSize:
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
    async def test_removing_the_original_keeps_a_copy_readable(self, ops):
        # Clients that implement a move as COPY + DELETE must not lose the
        # copy either, since both refs share the same telegram messages.
        await ops.upload_from_bytes(b"x" * 4321, "/src/file.txt")
        await ops.cp_file("/src/file.txt", "/dest/file.txt")

        await ops.rm_file("/src/file.txt")

        assert await size_of(ops, "/dest/file.txt") == 4321

    @pytest.mark.asyncio
    async def test_removing_the_last_reference_still_deletes_the_messages(self, ops):
        await ops.upload_from_bytes(b"x" * 77, "/src/file.txt")
        await ops.mv_file("/src/file.txt", "/dest/file.txt")

        await ops.rm_file("/dest/file.txt")

        assert cast(FakeClient, ops._client).channel.messages == {}

    @pytest.mark.asyncio
    async def test_removing_a_directory_keeps_a_copy_outside_it_readable(self, ops):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 555, "/src/sub/file.txt")
        await ops.cp_file("/src/sub/file.txt", "/dest/file.txt")

        await ops.rm_dir("/src/sub", True)

        assert await size_of(ops, "/dest/file.txt") == 555
