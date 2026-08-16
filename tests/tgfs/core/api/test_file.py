import pytest
import datetime

from tgfs.core.api.file import FileApi
from tgfs.core.api.file_desc import FileDescApi
from tgfs.core.api.message import MessageApi
from tgfs.core.api.metadata import MetaDataApi
from tgfs.core.model import TGFSDirectory, TGFSFileDesc, TGFSFileRef, TGFSFileVersion
from tgfs.errors import FileOrDirectoryAlreadyExists, FileOrDirectoryDoesNotExist
from tgfs.reqres import (
    FileMessage,
    FileMessageEmpty,
    FileMessageFromBuffer,
)


class TestFileApi:
    @pytest.fixture
    def mock_metadata_api(self, mocker):
        return mocker.AsyncMock(spec=MetaDataApi)

    @pytest.fixture
    def mock_file_desc_api(self, mocker):
        return mocker.AsyncMock(spec=FileDescApi)

    @pytest.fixture
    def mock_message_api(self, mocker):
        return mocker.AsyncMock(spec=MessageApi)

    @pytest.fixture
    def file_api(
        self, mock_metadata_api, mock_file_desc_api, mock_message_api
    ) -> FileApi:
        return FileApi(mock_metadata_api, mock_file_desc_api, mock_message_api)

    @pytest.fixture
    def sample_directory(self) -> TGFSDirectory:
        return TGFSDirectory.root_dir()

    @pytest.fixture
    def sample_file_ref(self, sample_directory) -> TGFSFileRef:
        return TGFSFileRef(
            message_id=123, name="test_file.txt", location=sample_directory
        )

    @pytest.fixture
    def sample_file_desc(self, mocker) -> TGFSFileDesc:
        # Create a mock TGFSFileDesc with necessary attributes
        file_desc = mocker.Mock(spec=TGFSFileDesc)
        file_desc.get_latest_version.return_value = TGFSFileVersion(
            id="v1",
            updated_at=datetime.datetime.now(),
            message_ids=[123],
            part_sizes=[1024],
        )
        return file_desc

    @pytest.fixture
    def sample_file_message(self) -> FileMessageFromBuffer:
        return FileMessageFromBuffer.new(buffer=b"test content", name="test_file.txt")

    def test_init(self, mock_metadata_api, mock_file_desc_api, mock_message_api):
        file_api = FileApi(mock_metadata_api, mock_file_desc_api, mock_message_api)

        assert file_api._metadata_api == mock_metadata_api
        assert file_api._file_desc_api == mock_file_desc_api
        assert file_api._message_api == mock_message_api

    @staticmethod
    def _fd_with_parts(*versions: tuple[str, list[int], list[int]]) -> TGFSFileDesc:
        fd = TGFSFileDesc(name="test_file.txt")
        for i, (version_id, message_ids, part_sizes) in enumerate(versions):
            fd.add_version(
                TGFSFileVersion(
                    id=version_id,
                    updated_at=datetime.datetime(2024, 1, 1 + i),
                    message_ids=list(message_ids),
                    part_sizes=list(part_sizes),
                )
            )
        return fd

    @pytest.mark.asyncio
    async def test_copy_duplicates_the_content_and_the_descriptor(
        self,
        file_api,
        mock_metadata_api,
        mock_file_desc_api,
        mock_message_api,
        sample_directory,
        sample_file_ref,
        mocker,
    ):
        mock_file_desc_api.get_file_desc.return_value = self._fd_with_parts(
            ("v1", [200, 201], [10, 20])
        )
        mock_message_api.duplicate_messages.return_value = [300, 301]
        resp = mocker.Mock()
        resp.message_id = 999
        resp.mirrors = {}
        mock_file_desc_api.save_new_file_desc.return_value = resp

        result = await file_api.copy(sample_directory, sample_file_ref)

        # The whole history is duplicated in a single call, and nothing is
        # uploaded: the copy points at fresh messages of its own.
        mock_message_api.duplicate_messages.assert_called_once_with([200, 201])
        copied_fd = mock_file_desc_api.save_new_file_desc.call_args[0][0]
        assert copied_fd.get_latest_version().message_ids == [300, 301]
        assert copied_fd.get_latest_version().part_sizes == [10, 20]
        assert result.message_id == 999
        assert result.message_id != sample_file_ref.message_id
        assert sample_directory.find_file("test_file.txt") is result
        mock_metadata_api.push.assert_called_once()

    @pytest.mark.asyncio
    async def test_copy_keeps_every_version(
        self,
        file_api,
        mock_file_desc_api,
        mock_message_api,
        sample_directory,
        sample_file_ref,
        mocker,
    ):
        source = self._fd_with_parts(
            ("v1", [200], [10]),
            ("v2", [201, 202], [20, 30]),
        )
        mock_file_desc_api.get_file_desc.return_value = source
        mock_message_api.duplicate_messages.return_value = [301, 302, 300]
        resp = mocker.Mock()
        resp.message_id = 999
        resp.mirrors = {}
        mock_file_desc_api.save_new_file_desc.return_value = resp

        await file_api.copy(sample_directory, sample_file_ref)

        mock_file_desc_api.get_file_desc.assert_called_once_with(
            sample_file_ref, include_all_versions=True
        )
        copied_fd = mock_file_desc_api.save_new_file_desc.call_args[0][0]
        # Both versions survive, with their timestamps and part sizes, but
        # under ids of their own -- the copy shares nothing with the source.
        assert not set(copied_fd.versions) & set(source.versions)
        by_stamp = {
            v.updated_at: v for v in copied_fd.get_versions()
        }
        assert by_stamp[source.get_version("v1").updated_at].message_ids == [300]
        assert by_stamp[source.get_version("v2").updated_at].message_ids == [301, 302]
        assert (
            copied_fd.get_latest_version().updated_at
            == source.get_latest_version().updated_at
        )
        assert copied_fd.created_at == source.created_at

    @pytest.mark.asyncio
    async def test_copy_with_custom_name(
        self,
        file_api,
        mock_file_desc_api,
        mock_message_api,
        sample_directory,
        sample_file_ref,
        mocker,
    ):
        mock_file_desc_api.get_file_desc.return_value = self._fd_with_parts(
            ("v1", [200], [10])
        )
        mock_message_api.duplicate_messages.return_value = [300]
        resp = mocker.Mock()
        resp.message_id = 999
        resp.mirrors = {}
        mock_file_desc_api.save_new_file_desc.return_value = resp

        result = await file_api.copy(
            sample_directory, sample_file_ref, "copied_file.txt"
        )

        assert result.name == "copied_file.txt"
        assert sample_directory.find_file("copied_file.txt") is result

    @pytest.mark.asyncio
    async def test_copy_discards_its_messages_when_it_cannot_finish(
        self,
        file_api,
        mock_file_desc_api,
        mock_message_api,
        sample_directory,
        sample_file_ref,
    ):
        mock_file_desc_api.get_file_desc.return_value = self._fd_with_parts(
            ("v1", [200], [10])
        )
        mock_message_api.duplicate_messages.return_value = [300]
        mock_file_desc_api.save_new_file_desc.side_effect = RuntimeError("channel down")

        with pytest.raises(RuntimeError):
            await file_api.copy(sample_directory, sample_file_ref)

        # Nothing refers to the duplicated message, so it must not linger.
        mock_message_api.delete_messages.assert_called_once_with([300], force=True)
        assert sample_directory.find_files() == []

    @pytest.mark.asyncio
    async def test_copy_discards_the_descriptor_of_a_rejected_name(
        self,
        file_api,
        mock_file_desc_api,
        mock_message_api,
        sample_directory,
        sample_file_ref,
        mocker,
    ):
        sample_directory.create_file_ref("test_file.txt", 1)
        mock_file_desc_api.get_file_desc.return_value = self._fd_with_parts(
            ("v1", [200], [10])
        )
        mock_message_api.duplicate_messages.return_value = [300]
        resp = mocker.Mock()
        resp.message_id = 999
        resp.mirrors = {}
        mock_file_desc_api.save_new_file_desc.return_value = resp

        with pytest.raises(FileOrDirectoryAlreadyExists):
            await file_api.copy(sample_directory, sample_file_ref)

        # The descriptor written a moment ago has to go as well.
        deleted = mock_message_api.delete_messages.call_args[0][0]
        assert sorted(deleted) == [300, 999]

    @pytest.mark.asyncio
    async def test_create_new_file(
        self,
        file_api,
        mock_metadata_api,
        mock_file_desc_api,
        sample_directory,
        sample_file_message,
        mocker,
    ):
        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = 456
        mock_response.fd = mocker.Mock(spec=TGFSFileDesc)
        mock_file_desc_api.create_file_desc.return_value = mock_response
        sample_directory.create_file_ref = mocker.Mock()

        result = await file_api._create_new_file(sample_directory, sample_file_message)

        mock_file_desc_api.create_file_desc.assert_called_once_with(sample_file_message)
        sample_directory.create_file_ref.assert_called_once_with(
            sample_file_message.name, mock_response.message_id
        )
        mock_metadata_api.push.assert_called_once()
        assert result == mock_response.fd

    @pytest.mark.asyncio
    async def test_sync_file_ref_no_update(
        self, file_api, mock_metadata_api, sample_file_ref, mocker
    ):
        resp = mocker.Mock()
        resp.message_id = sample_file_ref.message_id
        resp.mirrors = dict(sample_file_ref.mirrors)

        await file_api._sync_file_ref(sample_file_ref, resp)

        mock_metadata_api.push.assert_not_called()

    @pytest.mark.asyncio
    async def test_sync_file_ref_with_update(
        self, file_api, mock_metadata_api, sample_file_ref, mocker
    ):
        new_message_id = 999
        resp = mocker.Mock()
        resp.message_id = new_message_id
        resp.mirrors = {}

        await file_api._sync_file_ref(sample_file_ref, resp)

        assert sample_file_ref.message_id == new_message_id
        mock_metadata_api.push.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_existing_file_with_version_id(
        self, file_api, mock_file_desc_api, sample_file_ref, sample_file_message, mocker
    ):
        version_id = "v2"
        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = (
            sample_file_ref.message_id
        )  # Same ID, no update needed
        mock_response.fd = mocker.Mock(spec=TGFSFileDesc)
        mock_file_desc_api.update_file_version.return_value = mock_response

        result = await file_api._update_existing_file(
            sample_file_ref, sample_file_message, version_id
        )

        mock_file_desc_api.update_file_version.assert_called_once_with(
            sample_file_ref, sample_file_message, version_id
        )
        mock_file_desc_api.append_file_version.assert_not_called()
        assert result == mock_response.fd

    @pytest.mark.asyncio
    async def test_update_existing_file_without_version_id(
        self, file_api, mock_file_desc_api, sample_file_ref, sample_file_message, mocker
    ):
        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = (
            sample_file_ref.message_id
        )  # Same ID, no update needed
        mock_response.fd = mocker.Mock(spec=TGFSFileDesc)
        mock_file_desc_api.append_file_version.return_value = mock_response

        result = await file_api._update_existing_file(
            sample_file_ref, sample_file_message, None
        )

        mock_file_desc_api.append_file_version.assert_called_once_with(
            sample_file_message, sample_file_ref
        )
        mock_file_desc_api.update_file_version.assert_not_called()
        assert result == mock_response.fd

    @pytest.mark.asyncio
    async def test_rm_without_version_id(
        self,
        file_api,
        mock_metadata_api,
        mock_message_api,
        mock_file_desc_api,
        sample_file_ref,
        mocker,
    ):
        sample_file_ref.delete = mocker.Mock()

        fd = mocker.Mock(spec=TGFSFileDesc)
        fd.get_versions.return_value = [
            TGFSFileVersion(
                id="v1",
                updated_at=datetime.datetime.now(),
                message_ids=[200, 201],
            )
        ]
        mock_file_desc_api.get_file_desc.return_value = fd

        await file_api.rm(sample_file_ref)

        sample_file_ref.delete.assert_called_once()
        mock_metadata_api.push.assert_called_once()
        mock_message_api.delete_messages.assert_called_once()
        deleted_ids = mock_message_api.delete_messages.call_args[0][0]
        assert sorted(deleted_ids) == [123, 200, 201]

    @pytest.mark.asyncio
    async def test_rm_with_version_id(
        self,
        file_api,
        mock_file_desc_api,
        mock_message_api,
        sample_file_ref,
        mocker,
    ):
        version_id = "v1"
        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = (
            sample_file_ref.message_id
        )  # Same ID, no update needed
        mock_file_desc_api.delete_file_version.return_value = mock_response
        sample_file_ref.delete = mocker.Mock()

        fd = mocker.Mock(spec=TGFSFileDesc)
        fd.get_version.return_value = TGFSFileVersion(
            id=version_id,
            updated_at=datetime.datetime.now(),
            message_ids=[500, 501],
        )
        mock_file_desc_api.get_file_desc.return_value = fd

        await file_api.rm(sample_file_ref, version_id)

        mock_file_desc_api.delete_file_version.assert_called_once_with(
            sample_file_ref, version_id
        )
        sample_file_ref.delete.assert_not_called()
        mock_message_api.delete_messages.assert_called_once_with([500, 501])

    @pytest.mark.asyncio
    async def test_upload_non_uploadable_message_new_file(
        self, file_api, mock_file_desc_api, mock_metadata_api, sample_directory, mocker
    ):
        # Create a non-uploadable file message (regular FileMessage)
        file_msg = mocker.Mock(spec=FileMessage)
        file_msg.name = "test_file.txt"
        sample_directory.find_file = mocker.Mock(
            side_effect=FileOrDirectoryDoesNotExist("Not found")
        )

        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = 789
        mock_response.fd = mocker.Mock(spec=TGFSFileDesc)
        mock_file_desc_api.create_file_desc.return_value = mock_response
        sample_directory.create_file_ref = mocker.Mock()

        result = await file_api.upload(sample_directory, file_msg)

        sample_directory.find_file.assert_called_once_with(file_msg.name)
        mock_file_desc_api.create_file_desc.assert_called_once_with(file_msg)
        sample_directory.create_file_ref.assert_called_once_with(file_msg.name, 789)
        mock_metadata_api.push.assert_called_once()
        assert result == mock_response.fd

    @pytest.mark.asyncio
    async def test_upload_non_uploadable_message_existing_file(
        self, file_api, mock_file_desc_api, sample_directory, sample_file_ref, mocker
    ):
        # Create a non-uploadable file message (regular FileMessage)
        file_msg = mocker.Mock(spec=FileMessage)
        file_msg.name = "test_file.txt"
        sample_directory.find_file = mocker.Mock(return_value=sample_file_ref)

        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = (
            sample_file_ref.message_id
        )  # Same ID, no update needed
        mock_response.fd = mocker.Mock(spec=TGFSFileDesc)
        mock_file_desc_api.append_file_version.return_value = mock_response

        result = await file_api.upload(sample_directory, file_msg)

        sample_directory.find_file.assert_called_once_with(file_msg.name)
        mock_file_desc_api.append_file_version.assert_called_once_with(
            file_msg, sample_file_ref
        )
        assert result == mock_response.fd

    @pytest.mark.asyncio
    async def test_upload_uploadable_message_success(
        self,
        file_api,
        mock_file_desc_api,
        mock_metadata_api,
        sample_directory,
        sample_file_message,
        mocker,
    ):
        # Mock directory behavior for new file creation
        sample_directory.find_file = mocker.Mock(
            side_effect=FileOrDirectoryDoesNotExist("Not found")
        )
        sample_directory.create_file_ref = mocker.Mock()

        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = 789
        mock_response.fd = mocker.Mock(spec=TGFSFileDesc)
        mock_file_desc_api.create_file_desc.return_value = mock_response

        # Mock absolute_path property
        mocker.patch.object(
            type(sample_directory),
            "absolute_path",
            new_callable=mocker.PropertyMock,
            return_value="/test/path",
        )
        result = await file_api.upload(sample_directory, sample_file_message)

        # Verify file creation
        sample_directory.find_file.assert_called_once_with(sample_file_message.name)
        mock_file_desc_api.create_file_desc.assert_called_once_with(sample_file_message)
        assert result == mock_response.fd

    @pytest.mark.asyncio
    async def test_upload_uploadable_message_failure(
        self,
        file_api,
        mock_file_desc_api,
        sample_directory,
        sample_file_message,
        mocker,
    ):
        # Mock directory behavior for new file creation
        sample_directory.find_file = mocker.Mock(
            side_effect=FileOrDirectoryDoesNotExist("Not found")
        )

        # Mock file creation failure
        test_exception = Exception("Upload failed")
        mock_file_desc_api.create_file_desc.side_effect = test_exception

        # Mock absolute_path property
        mocker.patch.object(
            type(sample_directory),
            "absolute_path",
            new_callable=mocker.PropertyMock,
            return_value="/test/path",
        )

        with pytest.raises(Exception, match="Upload failed"):
            await file_api.upload(sample_directory, sample_file_message)

    @pytest.mark.asyncio
    async def test_desc(
        self, file_api, mock_file_desc_api, sample_file_ref, sample_file_desc
    ):
        mock_file_desc_api.get_file_desc.return_value = sample_file_desc

        result = await file_api.desc(sample_file_ref)

        mock_file_desc_api.get_file_desc.assert_called_once_with(sample_file_ref, False)
        assert result == sample_file_desc

    @pytest.mark.asyncio
    async def test_retrieve_empty_file(
        self, file_api, mock_file_desc_api, sample_file_ref
    ):
        # Mock an empty file descriptor
        empty_file_desc = FileMessageEmpty.new(name="empty.txt")
        mock_file_desc_api.get_file_desc.return_value = empty_file_desc

        result = await file_api.retrieve(sample_file_ref, 0, -1, "empty.txt")

        # Test that the result is an async generator that yields empty bytes
        chunks = []
        async for chunk in result:
            chunks.append(chunk)

        assert chunks == [b""]
        mock_file_desc_api.get_file_desc.assert_called_once_with(sample_file_ref, False)

    @pytest.mark.asyncio
    async def test_retrieve_regular_file(
        self, file_api, mock_file_desc_api, sample_file_ref, sample_file_desc
    ):
        mock_file_desc_api.get_file_desc.return_value = sample_file_desc

        # Mock the download method
        async def mock_download_chunks():
            yield b"chunk1"
            yield b"chunk2"

        mock_file_desc_api.download_file_at_version.return_value = (
            mock_download_chunks()
        )

        result = await file_api.retrieve(sample_file_ref, 0, 100, "test.txt")

        # Test that the result yields the expected chunks
        chunks = []
        async for chunk in result:
            chunks.append(chunk)

        assert chunks == [b"chunk1", b"chunk2"]
        mock_file_desc_api.get_file_desc.assert_called_once_with(sample_file_ref, False)
        mock_file_desc_api.download_file_at_version.assert_called_once()

    @pytest.mark.asyncio
    async def test_retrieve_with_exception(
        self, file_api, mock_file_desc_api, sample_file_ref, sample_file_desc
    ):
        mock_file_desc_api.get_file_desc.return_value = sample_file_desc

        # Mock the download method to raise an exception
        async def mock_download_chunks():
            raise Exception("Download failed")
            yield  # This will never execute

        mock_file_desc_api.download_file_at_version.return_value = (
            mock_download_chunks()
        )

        result = await file_api.retrieve(sample_file_ref, 0, 100, "test.txt")

        # Test that the exception is propagated
        with pytest.raises(Exception, match="Download failed"):
            async for chunk in result:
                pass

    @pytest.mark.asyncio
    async def test_retrieve_with_default_name(
        self, file_api, mock_file_desc_api, sample_file_ref, sample_file_desc
    ):
        mock_file_desc_api.get_file_desc.return_value = sample_file_desc

        # Mock the download method
        async def mock_download_chunks():
            yield b"data"

        mock_file_desc_api.download_file_at_version.return_value = (
            mock_download_chunks()
        )

        result = await file_api.retrieve(sample_file_ref, 0, 100, None)

        # Consume the iterator to trigger the call
        async for chunk in result:
            pass

        # Verify the call was made with the file_ref name as default
        call_args = mock_file_desc_api.download_file_at_version.call_args[0]
        assert call_args[3] == sample_file_ref.name  # as_name parameter

    @pytest.mark.asyncio
    async def test_retrieve_version(self, file_api, mock_file_desc_api):
        file_version = TGFSFileVersion(
            id="v1",
            updated_at=datetime.datetime.now(),
            message_ids=[123],
            part_sizes=[1024],
        )
        as_name = "version_file.txt"
        begin, end = 0, 500

        # Mock the download method
        async def mock_download_chunks():
            yield b"version_data"

        mock_file_desc_api.download_file_at_version.return_value = (
            mock_download_chunks()
        )

        result = await file_api.retrieve_version(file_version, begin, end, as_name)

        # Test that the result yields the expected chunks
        chunks = []
        async for chunk in result:
            chunks.append(chunk)

        assert chunks == [b"version_data"]
        mock_file_desc_api.download_file_at_version.assert_called_once_with(
            file_version, begin, end, as_name
        )

    @pytest.mark.asyncio
    async def test_upload_with_version_id(
        self,
        file_api,
        mock_file_desc_api,
        sample_directory,
        sample_file_ref,
        sample_file_message,
        mocker,
    ):
        version_id = "v3"
        sample_directory.find_file = mocker.Mock(return_value=sample_file_ref)

        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = (
            sample_file_ref.message_id
        )  # Same ID, no update needed
        mock_response.fd = mocker.Mock(spec=TGFSFileDesc)
        mock_file_desc_api.update_file_version.return_value = mock_response

        result = await file_api.upload(
            sample_directory, sample_file_message, version_id
        )

        sample_directory.find_file.assert_called_once_with(sample_file_message.name)
        mock_file_desc_api.update_file_version.assert_called_once_with(
            sample_file_ref, sample_file_message, version_id
        )
        assert result == mock_response.fd

    @pytest.mark.asyncio
    async def test_rm_with_version_id_message_id_update(
        self, file_api, mock_metadata_api, mock_file_desc_api, sample_file_ref, mocker
    ):
        version_id = "v1"
        new_message_id = 999
        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = new_message_id  # Different ID, update needed
        mock_file_desc_api.delete_file_version.return_value = mock_response

        fd = mocker.Mock(spec=TGFSFileDesc)
        fd.get_version.return_value = TGFSFileVersion(
            id=version_id,
            updated_at=datetime.datetime.now(),
            message_ids=[],
        )
        mock_file_desc_api.get_file_desc.return_value = fd

        await file_api.rm(sample_file_ref, version_id)

        mock_file_desc_api.delete_file_version.assert_called_once_with(
            sample_file_ref, version_id
        )
        # Verify message_id was updated
        assert sample_file_ref.message_id == new_message_id
        mock_metadata_api.push.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_existing_file_message_id_update(
        self,
        file_api,
        mock_metadata_api,
        mock_file_desc_api,
        sample_file_ref,
        sample_file_message,
        mocker,
    ):
        new_message_id = 888
        mock_response = mocker.Mock()
        mock_response.mirrors = {}
        mock_response.message_id = new_message_id  # Different ID, update needed
        mock_response.fd = mocker.Mock(spec=TGFSFileDesc)
        mock_file_desc_api.append_file_version.return_value = mock_response

        result = await file_api._update_existing_file(
            sample_file_ref, sample_file_message, None
        )

        mock_file_desc_api.append_file_version.assert_called_once_with(
            sample_file_message, sample_file_ref
        )
        # Verify message_id was updated
        assert sample_file_ref.message_id == new_message_id
        mock_metadata_api.push.assert_called_once()
        assert result == mock_response.fd

    @pytest.mark.asyncio
    async def test_move_relocates_ref_without_deleting_messages(
        self, file_api, mock_metadata_api, mock_message_api
    ):
        root = TGFSDirectory.root_dir()
        src = root.create_dir("src")
        dest = root.create_dir("dest")
        fr = src.create_file_ref("test_file.txt", 123)
        fr.mirrors = {"-100": 456}

        moved = await file_api.move(fr, dest)

        assert dest.find_file("test_file.txt") is moved
        assert src.find_files() == []
        # Same descriptor message, so the content stays reachable and the
        # reported size does not change.
        assert moved.message_id == 123
        assert moved.mirrors == {"-100": 456}
        mock_metadata_api.push.assert_called_once()
        mock_message_api.delete_messages.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_can_rename(self, file_api):
        root = TGFSDirectory.root_dir()
        src = root.create_dir("src")
        dest = root.create_dir("dest")
        fr = src.create_file_ref("test_file.txt", 123)

        moved = await file_api.move(fr, dest, "renamed.txt")

        assert dest.find_file("renamed.txt") is moved
        assert moved.message_id == 123

    @pytest.mark.asyncio
    async def test_move_onto_itself_is_a_noop(self, file_api, mock_metadata_api):
        root = TGFSDirectory.root_dir()
        src = root.create_dir("src")
        fr = src.create_file_ref("test_file.txt", 123)

        assert await file_api.move(fr, src) is fr
        assert src.find_files() == [fr]

    @pytest.mark.asyncio
    async def test_move_rejects_an_occupied_destination(self, file_api):
        root = TGFSDirectory.root_dir()
        src = root.create_dir("src")
        dest = root.create_dir("dest")
        fr = src.create_file_ref("test_file.txt", 123)
        dest.create_file_ref("test_file.txt", 456)

        with pytest.raises(FileOrDirectoryAlreadyExists):
            await file_api.move(fr, dest)

        # The source is untouched, so nothing is lost.
        assert src.find_file("test_file.txt") is fr

    @pytest.mark.asyncio
    async def test_rm_keeps_messages_shared_with_a_legacy_copy(
        self,
        file_api,
        mock_metadata_api,
        mock_message_api,
        mock_file_desc_api,
    ):
        # Copies made before copy-on-write existed share one descriptor
        # message, so removing either of them must leave the channel alone.
        root = TGFSDirectory.root_dir()
        mock_metadata_api.get_root_directory.return_value = root
        src = root.create_dir("src")
        dest = root.create_dir("dest")
        original = src.create_file_ref("test_file.txt", 123)
        legacy_copy = dest.create_file_ref("test_file.txt", 123)

        await file_api.rm(original)

        assert src.find_files() == []
        assert dest.find_file("test_file.txt") is legacy_copy
        mock_file_desc_api.get_file_desc.assert_not_called()
        mock_message_api.delete_messages.assert_called_once_with([])

    @pytest.mark.asyncio
    async def test_rm_deletes_messages_of_the_last_reference(
        self,
        file_api,
        mock_metadata_api,
        mock_message_api,
        mock_file_desc_api,
        mocker,
    ):
        root = TGFSDirectory.root_dir()
        mock_metadata_api.get_root_directory.return_value = root
        src = root.create_dir("src")
        fr = src.create_file_ref("test_file.txt", 123)

        fd = mocker.Mock(spec=TGFSFileDesc)
        fd.get_versions.return_value = [
            TGFSFileVersion(
                id="v1",
                updated_at=datetime.datetime.now(),
                message_ids=[200, 201],
            )
        ]
        mock_file_desc_api.get_file_desc.return_value = fd

        await file_api.rm(fr)

        deleted_ids = mock_message_api.delete_messages.call_args[0][0]
        assert sorted(deleted_ids) == [123, 200, 201]
