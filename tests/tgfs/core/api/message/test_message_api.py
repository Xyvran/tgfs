import pytest
from unittest.mock import Mock, AsyncMock
import asyncio

import telethon.types as tlt
from telethon.errors import MessageNotModifiedError, RPCError

from tgfs.config import TransferConfig
from tgfs.core.api.message import MessageApi
from tgfs.errors import (
    MessageNotFound,
    NoPinnedMessage,
    PinnedMessageNotSupported,
    TechnicalError,
)
from tgfs.reqres import (
    DeleteMessagesReq,
    DownloadFileReq,
    DownloadFileResp,
    EditMessageTextReq,
    GetPinnedMessageReq,
    MessageResp,
    MessageRespWithDocument,
    PinMessageReq,
    SearchMessageReq,
    SendMessageResp,
    SendTextReq,
    Document,
)
from tgfs.telegram.interface import TDLibApi


class TestMessageApi:
    @pytest.fixture
    def mock_tdlib(self, mocker):
        tdlib = mocker.Mock(spec=TDLibApi)
        tdlib.bots = [mocker.Mock(), mocker.Mock()]  # Mock multiple bots
        tdlib.next_bot = mocker.Mock()
        tdlib.account = mocker.Mock()

        # Make the methods async
        tdlib.next_bot.send_text = AsyncMock()
        tdlib.next_bot.edit_message_text = AsyncMock()
        tdlib.next_bot.pin_message = AsyncMock()
        tdlib.next_bot.download_file = AsyncMock()
        tdlib.next_bot.delete_messages = AsyncMock()
        tdlib.account.get_pinned_messages = AsyncMock()
        tdlib.account.search_messages = AsyncMock()

        return tdlib

    @pytest.fixture
    def mock_private_channel(self, mocker):
        return mocker.Mock(spec=tlt.PeerChannel)

    @pytest.fixture
    def message_api(self, mock_tdlib, mock_private_channel):
        return MessageApi(mock_tdlib, mock_private_channel)

    @pytest.fixture(autouse=True)
    def mock_rate_limiter(self, mocker):
        # Mock the rate limiter to avoid delays in tests
        mocker.patch("tgfs.core.api.message.limiter.try_acquire")

    @pytest.mark.asyncio
    async def test_send_text(self, message_api, mock_tdlib, mock_private_channel):
        # Setup
        mock_response = SendMessageResp(message_id=12345)
        mock_tdlib.next_bot.send_text.return_value = mock_response

        # Execute
        result = await message_api.send_text("Hello World")

        # Assert
        mock_tdlib.next_bot.send_text.assert_called_once_with(
            SendTextReq(chat=mock_private_channel, text="Hello World")
        )
        assert result == 12345

    @pytest.mark.asyncio
    async def test_edit_message_text_success(
        self, message_api, mock_tdlib, mock_private_channel
    ):
        # Setup
        mock_response = SendMessageResp(message_id=12345)
        mock_tdlib.next_bot.edit_message_text.return_value = mock_response

        # Execute
        result = await message_api.edit_message_text(12345, "Updated text")

        # Assert
        mock_tdlib.next_bot.edit_message_text.assert_called_once_with(
            EditMessageTextReq(
                chat=mock_private_channel,
                message_id=12345,
                text="Updated text",
            )
        )
        assert result == 12345

    @pytest.mark.asyncio
    async def test_edit_message_text_not_modified(self, message_api, mock_tdlib):
        # Setup
        mock_tdlib.next_bot.edit_message_text.side_effect = MessageNotModifiedError(
            "Not modified"
        )

        # Execute
        result = await message_api.edit_message_text(12345, "Same text")

        # Assert
        assert result == 12345

    @pytest.mark.asyncio
    async def test_edit_message_text_not_found(self, message_api, mock_tdlib):
        # Setup - create an RPCError that inherits from the real one
        from telethon.errors import RPCError as TelethonRPCError

        # Create a real telethon RPCError with a specific message pattern
        # Telethon RPCError typically expects (message, request, code) but we only care about message
        mock_error = TelethonRPCError(None, None)
        mock_error.message = "Message to edit not found"
        mock_tdlib.next_bot.edit_message_text.side_effect = mock_error

        # Execute & Assert
        with pytest.raises(MessageNotFound) as exc_info:
            await message_api.edit_message_text(12345, "New text")

        assert "12345" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_edit_message_text_not_modified_rpc_error(
        self, message_api, mock_tdlib
    ):
        # Setup - create an RPCError that inherits from the real one
        from telethon.errors import RPCError as TelethonRPCError

        # Create a real telethon RPCError with a specific message pattern
        mock_error = TelethonRPCError(None, None)
        mock_error.message = "Message is not modified"
        mock_tdlib.next_bot.edit_message_text.side_effect = mock_error

        # Execute
        result = await message_api.edit_message_text(12345, "Same text")

        # Assert
        assert result == 12345

    @pytest.mark.asyncio
    async def test_edit_message_text_other_rpc_error(
        self, message_api, mock_tdlib, mocker
    ):
        # Setup
        mock_error = mocker.Mock(spec=RPCError)
        mock_error.message = "Some other error"
        mock_tdlib.next_bot.edit_message_text.side_effect = mock_error

        # Execute & Assert
        with pytest.raises(Exception):  # Will raise the mock error
            await message_api.edit_message_text(12345, "New text")

    @pytest.mark.asyncio
    async def test_get_pinned_message_no_account(self, message_api, mock_tdlib):
        # Setup
        mock_tdlib.account = None

        # Execute & Assert
        with pytest.raises(PinnedMessageNotSupported):
            await message_api.get_pinned_message()

    @pytest.mark.asyncio
    async def test_get_pinned_message_no_pinned_messages(
        self, message_api, mock_tdlib, mock_private_channel
    ):
        # Setup
        mock_tdlib.account.get_pinned_messages.return_value = []

        # Execute & Assert
        with pytest.raises(NoPinnedMessage):
            await message_api.get_pinned_message()

        mock_tdlib.account.get_pinned_messages.assert_called_once_with(
            GetPinnedMessageReq(chat=mock_private_channel)
        )

    @pytest.mark.asyncio
    async def test_get_pinned_message_no_document(self, message_api, mock_tdlib):
        # Setup
        mock_message = MessageResp(message_id=123, text="test", document=None)
        mock_tdlib.account.get_pinned_messages.return_value = [mock_message]

        # Execute & Assert
        with pytest.raises(
            TechnicalError, match="Pinned message does not contain a document"
        ):
            await message_api.get_pinned_message()

    @pytest.mark.asyncio
    async def test_get_pinned_message_success(self, message_api, mock_tdlib):
        # Setup
        mock_document = Document(
            id=456,
            size=1024,
            access_hash=789,
            file_reference=b"test_ref",
            mime_type="text/plain",
        )
        mock_message = MessageResp(message_id=123, text="test", document=mock_document)
        mock_tdlib.account.get_pinned_messages.return_value = [mock_message]

        # Execute
        result = await message_api.get_pinned_message()

        # Assert
        assert isinstance(result, MessageRespWithDocument)
        assert result.message_id == 123
        assert result.document == mock_document
        assert result.text == ""

    @pytest.mark.asyncio
    async def test_pin_message(self, message_api, mock_tdlib, mock_private_channel):
        # Execute
        await message_api.pin_message(12345)

        # Assert
        mock_tdlib.next_bot.pin_message.assert_called_once_with(
            PinMessageReq(chat=mock_private_channel, message_id=12345)
        )

    @pytest.mark.asyncio
    async def test_search_messages_with_account(
        self, message_api, mock_tdlib, mock_private_channel
    ):
        # Setup
        mock_messages = [
            MessageResp(message_id=1, text="test1", document=None),
            MessageResp(message_id=2, text="test2", document=None),
            None,  # This should be filtered out
        ]
        mock_tdlib.account.search_messages.return_value = mock_messages

        # Execute
        result = await message_api.search_messages("test query")

        # Assert
        mock_tdlib.account.search_messages.assert_called_once_with(
            SearchMessageReq(chat=mock_private_channel, search="test query")
        )
        assert len(result) == 2
        assert result[0].message_id == 1
        assert result[1].message_id == 2

    @pytest.mark.asyncio
    async def test_search_messages_no_account(self, message_api, mock_tdlib):
        # Setup
        mock_tdlib.account = None

        # Execute
        result = await message_api.search_messages("test query")

        # Assert
        assert result == []

    def test_split_download_pieces(self):
        pieces = list(MessageApi.split_download_pieces(0, 299, 100))

        assert pieces == [(0, 99), (100, 199), (200, 299)]

    def test_split_download_pieces_uneven(self):
        """The last piece is short; it is never padded past ``end``."""
        pieces = list(MessageApi.split_download_pieces(0, 10, 4))

        assert pieces == [(0, 3), (4, 7), (8, 10)]

    def test_split_download_pieces_shorter_than_one_piece(self):
        pieces = list(MessageApi.split_download_pieces(10, 19, 4096))

        assert pieces == [(10, 19)]

    def test_size_calculation(self):
        # _size counts the bytes of an inclusive range
        assert MessageApi._size(0, 10) == 11
        assert MessageApi._size(0, 0) == 1
        assert MessageApi._size(100, 199) == 100

    @pytest.mark.asyncio
    async def test_download_file_small(
        self,
        message_api,
        mock_tdlib,
        mock_private_channel,
        mocker,
    ):
        # A range far below the threshold is fetched in one go
        mock_response = Mock(spec=DownloadFileResp, chunks=AsyncMock(), size=100)
        mock_tdlib.next_bot.download_file.return_value = mock_response

        # Execute
        result = await message_api.download_file(12345, 0, 99)

        # Assert
        mock_tdlib.next_bot.download_file.assert_called_once()
        call_args = mock_tdlib.next_bot.download_file.call_args[0][0]
        assert isinstance(call_args, DownloadFileReq)
        assert call_args.chat == mock_private_channel
        assert call_args.message_id == 12345
        assert call_args.chunk_size == 512
        assert call_args.begin == 0
        assert call_args.end == 99
        assert result == mock_response

    @staticmethod
    def _transfer_settings(mocker, **overrides) -> TransferConfig:
        """Point the download tunables at test-sized values."""
        settings = TransferConfig.from_dict(
            {"parallel_download_threshold_mb": 1, **overrides}
        )
        mocker.patch("tgfs.core.api.message._transfer", return_value=settings)
        return settings

    @staticmethod
    def _serve_ranges(mock_tdlib):
        """Answer each download_file call with the bytes of its own range."""
        requested = []

        async def download(req: DownloadFileReq) -> DownloadFileResp:
            requested.append((req.begin, req.end))
            payload = bytes([req.begin % 251]) * (req.end - req.begin + 1)

            async def chunks():
                yield payload

            return DownloadFileResp(chunks=chunks(), size=len(payload))

        mock_tdlib.next_bot.download_file = AsyncMock(side_effect=download)
        return requested

    @pytest.mark.asyncio
    async def test_download_file_parallel(self, message_api, mock_tdlib, mocker):
        """A big range is fetched piece by piece and delivered in order."""
        piece = 1024 * 1024
        self._transfer_settings(mocker, download_piece_size_kb=1024)
        requested = self._serve_ranges(mock_tdlib)

        result = await message_api.download_file(12345, 0, 4 * piece - 1)
        received = b"".join([chunk async for chunk in result.chunks])

        assert requested == [
            (0, piece - 1),
            (piece, 2 * piece - 1),
            (2 * piece, 3 * piece - 1),
            (3 * piece, 4 * piece - 1),
        ]
        assert result.size == 4 * piece
        assert received == b"".join(
            bytes([begin % 251]) * piece for begin, _ in requested
        )

    @pytest.mark.asyncio
    async def test_download_file_parallel_starts_pieces_lazily(
        self, message_api, mock_tdlib, mocker
    ):
        """Pieces beyond the window must not be requested up front.

        A multi-gigabyte range is hundreds of pieces; issuing them all at
        once would replace one slow download with a burst of requests.
        """
        self._transfer_settings(
            mocker, download_piece_size_kb=1024, download_pieces_in_flight=2
        )
        requested = self._serve_ranges(mock_tdlib)

        result = await message_api.download_file(12345, 0, 20 * 1024 * 1024 - 1)
        await result.chunks.__anext__()
        await asyncio.sleep(0)

        assert len(requested) <= 4
        await result.chunks.aclose()

    @pytest.mark.asyncio
    async def test_download_file_parallel_short_range_is_a_single_piece(
        self, message_api, mock_tdlib, mocker
    ):
        self._transfer_settings(mocker)
        requested = self._serve_ranges(mock_tdlib)

        # Past the threshold, but still shorter than a single piece
        end = 2 * 1024 * 1024 - 1
        result = await message_api.download_file(12345, 0, end)
        async for _ in result.chunks:
            pass

        assert requested == [(0, end)]

    @pytest.fixture
    def patch_delete_flag(self, mocker):
        def _patch(enabled: bool):
            cfg = mocker.Mock()
            cfg.telegram.delete_messages_on_remove = enabled
            mocker.patch("tgfs.core.api.message.get_config", return_value=cfg)

        return _patch

    @pytest.mark.asyncio
    async def test_delete_messages_disabled_no_call(
        self, message_api, mock_tdlib, patch_delete_flag
    ):
        patch_delete_flag(False)

        await message_api.delete_messages([1, 2, 3])

        mock_tdlib.next_bot.delete_messages.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_messages_enabled(
        self, message_api, mock_tdlib, mock_private_channel, patch_delete_flag
    ):
        patch_delete_flag(True)

        await message_api.delete_messages([10, 20, 30])

        mock_tdlib.next_bot.delete_messages.assert_called_once()
        req: DeleteMessagesReq = (
            mock_tdlib.next_bot.delete_messages.call_args[0][0]
        )
        assert req.chat == mock_private_channel
        assert set(req.message_ids) == {10, 20, 30}

    @pytest.mark.asyncio
    async def test_delete_messages_empty_no_call(
        self, message_api, mock_tdlib, patch_delete_flag
    ):
        patch_delete_flag(True)

        await message_api.delete_messages([])
        await message_api.delete_messages([0, -1])

        mock_tdlib.next_bot.delete_messages.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_messages_dedupes(
        self, message_api, mock_tdlib, patch_delete_flag
    ):
        patch_delete_flag(True)

        await message_api.delete_messages([5, 5, 5, 6])

        assert mock_tdlib.next_bot.delete_messages.call_count == 1
        req = mock_tdlib.next_bot.delete_messages.call_args[0][0]
        assert sorted(req.message_ids) == [5, 6]

    @pytest.mark.asyncio
    async def test_delete_messages_batches_above_limit(
        self, message_api, mock_tdlib, patch_delete_flag
    ):
        patch_delete_flag(True)

        ids = list(range(1, 251))  # 250 ids -> 100 + 100 + 50
        await message_api.delete_messages(ids)

        assert mock_tdlib.next_bot.delete_messages.call_count == 3
        sizes = [
            len(call.args[0].message_ids)
            for call in mock_tdlib.next_bot.delete_messages.call_args_list
        ]
        assert sorted(sizes) == [50, 100, 100]

    @pytest.mark.asyncio
    async def test_delete_messages_swallows_errors(
        self, message_api, mock_tdlib, patch_delete_flag
    ):
        patch_delete_flag(True)
        mock_tdlib.next_bot.delete_messages.side_effect = RuntimeError("boom")

        # Should not raise.
        await message_api.delete_messages([1, 2])

    @pytest.mark.asyncio
    async def test_download_file_end_zero_or_negative(self, message_api, mock_tdlib):
        # Setup
        mock_response = Mock(spec=DownloadFileResp, chunks=AsyncMock(), size=100)
        mock_tdlib.next_bot.download_file.return_value = mock_response

        # Execute with end <= 0
        result = await message_api.download_file(12345, 0, 0)

        # Assert - should not use parallel download regardless of size
        mock_tdlib.next_bot.download_file.assert_called_once()
        assert result == mock_response

    @pytest.mark.asyncio
    async def test_duplicate_messages_forwards_in_one_call(
        self, message_api, mock_tdlib
    ):
        mock_tdlib.next_bot.forward_messages = AsyncMock(
            return_value=[SendMessageResp(message_id=11), SendMessageResp(message_id=12)]
        )

        result = await message_api.duplicate_messages([1, 2])

        req = mock_tdlib.next_bot.forward_messages.call_args[0][0]
        # Forwarding is server-side: the documents are not moved, and source
        # and target are the very same channel.
        assert req.from_chat == req.to_chat == message_api.private_file_channel
        assert req.message_ids == (1, 2)
        assert result == [11, 12]

    @pytest.mark.asyncio
    async def test_duplicate_messages_without_ids_calls_nothing(
        self, message_api, mock_tdlib
    ):
        mock_tdlib.next_bot.forward_messages = AsyncMock()

        assert await message_api.duplicate_messages([]) == []

        mock_tdlib.next_bot.forward_messages.assert_not_called()

    @pytest.mark.asyncio
    async def test_duplicate_messages_falls_back_to_reupload(
        self, message_api, mock_tdlib, mocker
    ):
        # Channels with "restrict saving content" reject forwarding.
        mock_tdlib.next_bot.forward_messages = AsyncMock(
            side_effect=RuntimeError("CHAT_FORWARDS_RESTRICTED")
        )
        reupload = mocker.patch.object(
            MessageApi, "reupload_to", new=AsyncMock(side_effect=[21, 22])
        )

        result = await message_api.duplicate_messages([1, 2])

        assert result == [21, 22]
        assert [call.args[0] for call in reupload.call_args_list] == [1, 2]
        assert all(
            call.args[1] == message_api.private_file_channel
            for call in reupload.call_args_list
        )

    @pytest.mark.asyncio
    async def test_reupload_to_streams_the_document_verbatim(
        self, message_api, mock_tdlib, mocker
    ):
        message = MessageResp(
            message_id=1,
            text="",
            document=Document(
                size=64,
                id=1,
                access_hash=0,
                file_reference=b"",
                mime_type="application/octet-stream",
            ),
        )
        mocker.patch.object(
            MessageApi, "get_messages", new=AsyncMock(return_value=[message])
        )
        chunks = AsyncMock()
        download = mocker.patch.object(
            MessageApi,
            "download_file",
            new=AsyncMock(return_value=Mock(spec=DownloadFileResp, chunks=chunks)),
        )
        uploader = Mock()
        uploader.upload = AsyncMock()
        uploader.send = AsyncMock(return_value=SendMessageResp(message_id=99))
        uploader_cls = mocker.patch(
            "tgfs.core.repository.impl.file_content.file_uploader.FileUploader",
            return_value=uploader,
        )

        result = await message_api.reupload_to(1, 4242)

        assert result == 99
        # The whole document is read, and the bytes go over untouched -- this
        # runs below the encryption layer, so ciphertext stays ciphertext.
        download.assert_awaited_once_with(1, 0, 63)
        assert uploader_cls.call_args[0][1].stream is chunks
        uploader.send.assert_awaited_once_with(4242)

    @pytest.mark.asyncio
    async def test_reupload_to_rejects_a_message_without_a_document(
        self, message_api, mocker
    ):
        mocker.patch.object(
            MessageApi,
            "get_messages",
            new=AsyncMock(return_value=[MessageResp(message_id=1, text="", document=None)]),
        )

        with pytest.raises(MessageNotFound):
            await message_api.reupload_to(1, 4242)
