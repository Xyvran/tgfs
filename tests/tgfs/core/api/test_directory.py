import datetime

import pytest

from tgfs.core.api.directory import DirectoryApi
from tgfs.core.api.file import FileApi
from tgfs.core.api.message import MessageApi
from tgfs.core.api.metadata import MetaDataApi
from tgfs.core.model import TGFSDirectory, TGFSFileRef, TGFSFileVersion
from tgfs.errors import DirectoryIsNotEmpty


class TestDirectoryApi:
    @pytest.fixture
    def mock_metadata_api(self, mocker):
        return mocker.AsyncMock(spec=MetaDataApi)

    @pytest.fixture
    def mock_file_api(self, mocker):
        return mocker.AsyncMock(spec=FileApi)

    @pytest.fixture
    def mock_message_api(self, mocker):
        return mocker.AsyncMock(spec=MessageApi)

    @pytest.fixture
    def dir_api(self, mock_metadata_api, mock_file_api, mock_message_api) -> DirectoryApi:
        return DirectoryApi(mock_metadata_api, mock_file_api, mock_message_api)

    @staticmethod
    def _make_version(message_ids):
        return TGFSFileVersion(
            id="v1",
            updated_at=datetime.datetime.now(),
            message_ids=list(message_ids),
        )

    @pytest.mark.asyncio
    async def test_rm_empty_directory_no_messages_to_delete(
        self, dir_api, mock_metadata_api, mock_file_api, mock_message_api
    ):
        empty_dir = TGFSDirectory.root_dir()
        mock_file_api.collect_deletable_message_ids.return_value = ([], {})

        await dir_api.rm_empty(empty_dir)

        mock_metadata_api.push.assert_called_once()
        mock_message_api.delete_messages.assert_called_once_with([])

    @pytest.mark.asyncio
    async def test_rm_empty_non_empty_raises(self, dir_api):
        d = TGFSDirectory.root_dir()
        d.create_file_ref("a.txt", 1)

        with pytest.raises(DirectoryIsNotEmpty):
            await dir_api.rm_empty(d)

    @pytest.mark.asyncio
    async def test_rm_dangerously_collects_subtree_message_ids(
        self, dir_api, mock_file_api, mock_message_api, mock_metadata_api
    ):
        root = TGFSDirectory.root_dir()
        root.create_file_ref("top.txt", 10)

        sub = root.create_dir("sub")
        sub.create_file_ref("inner.txt", 20)

        async def fake_collect(frs: list[TGFSFileRef]):
            # Real impl returns, for every ref whose messages are not shared
            # with a file outside the subtree, the FD message id plus the
            # version content ids and a per-mirror-channel id map.
            ids = []
            for fr in frs:
                if fr.message_id == 10:
                    ids.extend([10, 100, 101])
                elif fr.message_id == 20:
                    ids.extend([20, 200])
            return ids, {}

        mock_file_api.collect_deletable_message_ids.side_effect = fake_collect

        await dir_api.rm_dangerously(root)

        collected = mock_file_api.collect_deletable_message_ids.call_args[0][0]
        assert sorted(fr.message_id for fr in collected) == [10, 20]

        mock_metadata_api.push.assert_called_once()
        mock_message_api.delete_messages.assert_called_once()
        deleted = mock_message_api.delete_messages.call_args[0][0]
        assert sorted(deleted) == [10, 20, 100, 101, 200]

    @pytest.mark.asyncio
    async def test_move_reparents_without_touching_messages(
        self, dir_api, mock_metadata_api, mock_message_api
    ):
        root = TGFSDirectory.root_dir()
        src = root.create_dir("src")
        dest = root.create_dir("dest")
        moved_me = src.create_dir("moved_me")
        moved_me.create_file_ref("inner.txt", 20)

        result = await dir_api.move(moved_me, dest)

        assert result is moved_me
        assert moved_me.parent is dest
        assert dest.find_dir("moved_me") is moved_me
        assert src.find_dirs() == []
        # The subtree still points at the very same descriptor message.
        assert moved_me.find_file("inner.txt").message_id == 20
        mock_metadata_api.push.assert_called_once()
        mock_message_api.delete_messages.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_can_rename(self, dir_api):
        root = TGFSDirectory.root_dir()
        src = root.create_dir("src")
        dest = root.create_dir("dest")

        await dir_api.move(src, dest, "renamed")

        assert dest.find_dir("renamed") is src
        assert src.name == "renamed"
