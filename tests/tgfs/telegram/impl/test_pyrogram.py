from unittest.mock import AsyncMock, Mock

import pytest
from pyrogram import Client, file_id
from pyrogram import types as t

from tgfs.errors import TechnicalError
from tgfs.reqres import DownloadFileReq
from tgfs.telegram.impl.pyrogram import GET_FILE_CHUNK_SIZE, PyrogramAPI


class TestPyrogramDownload:
    @pytest.fixture
    def mock_client(self, mocker) -> AsyncMock:
        client = mocker.AsyncMock(spec=Client)
        client.get_messages = mocker.AsyncMock()
        return client

    @pytest.fixture
    def api(self, mock_client) -> PyrogramAPI:
        return PyrogramAPI(mock_client)

    @pytest.fixture
    def document_message(self, mocker):
        mocker.patch.object(file_id.FileId, "decode", return_value=Mock())
        message = mocker.Mock(spec=t.Message)
        message.id = 54321
        message.document = mocker.Mock(file_id="encoded")
        return message

    @staticmethod
    def _serve(api, calls, *chunks):
        def get_file(**kwargs):
            calls.append(kwargs)

            async def gen():
                for chunk in chunks:
                    yield chunk

            return gen()

        api._client.get_file = get_file

    @pytest.mark.asyncio
    async def test_offset_is_counted_in_chunks(self, api, document_message):
        """``get_file`` takes its offset in 1 MiB chunks, so a byte offset
        is converted and the bytes before it, served first, are dropped."""
        api._client.get_messages.return_value = document_message
        calls: list[dict] = []
        self._serve(api, calls, b"ab", b"cd", b"efgh", b"ijkl")

        begin = 3 * GET_FILE_CHUNK_SIZE + 3
        resp = await api.download_file(
            DownloadFileReq(chat=1, message_id=54321, begin=begin, end=begin + 6)
        )
        chunks = [chunk async for chunk in resp.chunks]

        assert calls[0]["offset"] == 3
        assert chunks == [b"d", b"efgh", b"ij"]

    @pytest.mark.asyncio
    async def test_fails_when_the_stream_ends_early(self, api, document_message):
        api._client.get_messages.return_value = document_message
        self._serve(api, [], b"12345678")

        resp = await api.download_file(
            DownloadFileReq(chat=1, message_id=54321, begin=0, end=99)
        )

        with pytest.raises(TechnicalError, match="ended after 8 of 100 bytes"):
            async for _ in resp.chunks:
                pass
