import asyncio
import logging
from typing import AsyncIterator, Iterable, Iterator, List, Optional, Set

from pyrate_limiter import Duration, InMemoryBucket, Limiter, Rate
from telethon.errors import MessageNotModifiedError, RPCError

from tgfs.config import TransferConfig, get_config
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
    FileMessageFromStream,
    ForwardMessagesReq,
    GetPinnedMessageReq,
    MessageResp,
    MessageRespWithDocument,
    PinMessageReq,
    SearchMessageReq,
    SendTextReq,
)
from tgfs.telegram.interface import TDLibApi
from tgfs.utils.chunk_cache import (
    block_bounds,
    block_length,
    block_range,
    chunk_cache,
)
from tgfs.utils.others import exclude_none
from tgfs.utils.prefetching_chain import prefetching_chain

from .message_broker import MessageBroker

logger = logging.getLogger(__name__)


def _transfer() -> TransferConfig:
    return get_config().tgfs.transfer

# Telegram's messages.deleteMessages caps each request at 100 message ids.
DELETE_BATCH_SIZE = 100

# Read-ahead is speculative, so it must never crowd out the requests someone
# is actually waiting on.
MAX_READAHEAD_TASKS = 4

# Telegram addresses file content in 4 KiB units, so nothing smaller can
# arrive as a chunk. Used only to turn a byte budget into a queue length.
MIN_STREAM_CHUNK = 4096


rate = Rate(20, Duration.SECOND)
bucket = InMemoryBucket([rate])
limiter = Limiter(bucket, max_delay=60 * 1000)  # 60 seconds max delay


class MessageApi(MessageBroker):
    def __init__(self, tdlib: TDLibApi, private_file_channel: int):
        super().__init__(tdlib, private_file_channel)
        self.__readahead: Set[tuple[int, int, int]] = set()

    @staticmethod
    def __try_acquire(name: str):
        limiter.try_acquire(name)

    async def send_text(self, message: str) -> int:
        self.__try_acquire("MessageApi.send_text")
        return (
            await self.tdlib.next_bot.send_text(
                SendTextReq(chat=self.private_file_channel, text=message)
            )
        ).message_id

    async def edit_message_text(self, message_id: int, message: str) -> int:
        self.__try_acquire("MessageApi.edit_message_text")
        try:
            return (
                await self.tdlib.next_bot.edit_message_text(
                    EditMessageTextReq(
                        chat=self.private_file_channel,
                        message_id=message_id,
                        text=message,
                    )
                )
            ).message_id
        except MessageNotModifiedError:
            return message_id
        except RPCError as e:
            if e.message == "Message to edit not found":
                raise MessageNotFound(message_id=message_id)
            if e.message == "Message is not modified":
                return message_id
            raise e

    async def get_pinned_message(self) -> MessageRespWithDocument:
        self.__try_acquire("MessageApi.get_pinned_message")

        if not self.tdlib.account:
            raise PinnedMessageNotSupported()
        messages = await self.tdlib.account.get_pinned_messages(
            GetPinnedMessageReq(chat=self.private_file_channel)
        )

        if len(messages) == 0:
            raise NoPinnedMessage()

        if (message := messages[0]).document is None:
            raise TechnicalError("Pinned message does not contain a document")

        return MessageRespWithDocument(
            message_id=message.message_id,
            document=message.document,
            text="",
        )

    async def forward_messages_from(
        self, source_channel: int, message_ids: List[int]
    ) -> List[int]:
        """Server-side copy of messages from ``source_channel`` into this
        channel. Returns the new message ids, aligned with the input."""
        self.__try_acquire("MessageApi.forward_messages_from")
        resp = await self.tdlib.next_bot.forward_messages(
            ForwardMessagesReq(
                from_chat=source_channel,
                to_chat=self.private_file_channel,
                message_ids=tuple(message_ids),
            )
        )
        return [m.message_id for m in resp]

    async def reupload_to(self, message_id: int, to_channel: int) -> int:
        """Bandwidth-bound copy: stream a document down and up again.

        The fallback for channels where forwarding is impossible
        ("restrict saving content"). Bytes are copied verbatim -- this
        sits below the encryption decorator, so ciphertext stays
        ciphertext and is never encrypted twice. The document name is
        not preserved; names live in the TGFS metadata, so nothing
        user-visible depends on it.
        """
        # Imported here to avoid a circular import at module load time.
        from tgfs.core.repository.impl.file_content.file_uploader import FileUploader

        message = (await self.get_messages([message_id]))[0]
        if not message or not message.document:
            raise MessageNotFound(message_id=message_id)
        size = message.document.size
        resp = await self.download_file(message_id, 0, size - 1)
        file_msg = FileMessageFromStream.new(
            stream=resp.chunks, size=size, name=f"part-{message_id}"
        )
        uploader = FileUploader(self.tdlib.next_bot, file_msg)
        await uploader.upload()
        sent = await uploader.send(to_channel)
        return sent.message_id

    async def duplicate_messages(self, message_ids: List[int]) -> List[int]:
        """Copy messages within this channel, without moving their bytes.

        Forwarding is a server-side operation: the new messages point at
        the documents that are already on Telegram, so a copy costs one
        API call no matter how large the file is. Channels with
        "restrict saving content" reject forwarding, so fall back to
        streaming each part down and up again.
        """
        if not message_ids:
            return []
        try:
            return await self.forward_messages_from(
                self.private_file_channel, message_ids
            )
        except Exception as ex:
            logger.warning(
                f"Could not forward {len(message_ids)} message(s) inside channel "
                f"{self.private_file_channel} ({ex}); falling back to re-upload"
            )
            return [
                await self.reupload_to(message_id, self.private_file_channel)
                for message_id in message_ids
            ]

    async def delete_messages(
        self, message_ids: Iterable[int], force: bool = False
    ) -> None:
        """Best-effort deletion of channel messages.

        Gated by ``telegram.delete_messages_on_remove`` so the default
        TGFS behavior (file removed from metadata, message kept on the
        channel) is unchanged. Failures are logged but never raised --
        the caller has already committed the metadata change and we do
        not want a delete error to roll that back.

        ``force=True`` bypasses the config gate; it is used for internal
        bookkeeping messages (e.g. a superseded mirrored metadata blob)
        that should never linger regardless of the user's preference for
        keeping removed *file* messages.
        """
        if not force and not get_config().telegram.delete_messages_on_remove:
            return
        unique_ids: List[int] = list({mid for mid in message_ids if mid > 0})
        if not unique_ids:
            return
        for start in range(0, len(unique_ids), DELETE_BATCH_SIZE):
            batch = tuple(unique_ids[start : start + DELETE_BATCH_SIZE])
            self.__try_acquire("MessageApi.delete_messages")
            try:
                await self.tdlib.next_bot.delete_messages(
                    DeleteMessagesReq(
                        chat=self.private_file_channel,
                        message_ids=batch,
                    )
                )
            except Exception as ex:
                logger.warning(
                    f"Failed to delete telegram messages {batch} from channel "
                    f"{self.private_file_channel}: {ex}"
                )

    async def pin_message(self, message_id: int):
        self.__try_acquire("MessageApi.pin_message")
        return await self.tdlib.next_bot.pin_message(
            PinMessageReq(chat=self.private_file_channel, message_id=message_id)
        )

    async def search_messages(self, search: str) -> list[MessageResp]:
        self.__try_acquire("MessageApi.search_messages")
        if self.tdlib.account:
            return list(
                exclude_none(
                    await self.tdlib.account.search_messages(
                        SearchMessageReq(chat=self.private_file_channel, search=search)
                    )
                )
            )
        return []

    @staticmethod
    def split_download_pieces(
        begin: int, end: int, piece_size: int
    ) -> Iterator[tuple[int, int]]:
        """Cut the inclusive range ``[begin, end]`` into pieces."""
        for piece_begin in range(begin, end + 1, piece_size):
            yield piece_begin, min(piece_begin + piece_size - 1, end)

    @staticmethod
    def _size(begin: int, end: int) -> int:
        """Number of bytes in the inclusive range ``[begin, end]``."""
        return end - begin + 1

    def _download_piece(
        self, message_id: int, begin: int, end: int
    ) -> AsyncIterator[bytes]:
        """One piece of a split download.

        A generator, so the request is issued when the piece is actually
        started. Building them eagerly would fire one call per piece up
        front -- hundreds of them for a large file.
        """

        async def piece() -> AsyncIterator[bytes]:
            resp = await self.tdlib.next_bot.download_file(
                DownloadFileReq(
                    chat=self.private_file_channel,
                    message_id=message_id,
                    begin=begin,
                    end=end,
                )
            )
            async for chunk in resp.chunks:
                yield chunk

        return piece()

    async def download_file_parallel(
        self, message_id: int, begin: int, end: int
    ) -> DownloadFileResp:
        transfer = _transfer()
        piece_size = transfer.download_piece_size_bytes

        pieces = [
            self._download_piece(message_id, piece_begin, piece_end)
            for piece_begin, piece_end in self.split_download_pieces(
                begin, end, piece_size
            )
        ]

        # A piece has to fit in its queue, otherwise a piece that is ready
        # early blocks instead of freeing its bot for the next one -- which
        # is what would keep the download sequential in all but name. The
        # queue counts chunks, whose size the Telegram library picks, so the
        # bound is derived from the smallest one it could hand out. This does
        # not risk memory: a source here is a single piece, so it cannot
        # produce more than one piece worth of bytes however deep its queue.
        queue_depth = max(1, -(-piece_size // MIN_STREAM_CHUNK))

        return DownloadFileResp(
            chunks=prefetching_chain(
                pieces,
                concurrency=transfer.download_pieces_in_flight,
                queue_depth=queue_depth,
            ),
            size=self._size(begin, end),
        )

    async def _document_size(self, message_id: int) -> Optional[int]:
        """On-wire size of a file message, or ``None`` if it is not one."""
        messages = await self.get_messages([message_id])
        if not (message := messages[0]) or not message.document:
            return None
        return message.document.size

    async def _fetch_blocks(
        self, message_id: int, first: int, last: int, size: int, block_size: int
    ) -> AsyncIterator[tuple[int, bytes, bool]]:
        """Fetch blocks ``first..last`` and cut the stream back into blocks.

        Yields ``(index, data, complete)``. A block is complete when it has
        the length it should have for its position -- the final block of a
        document is legitimately short, a truncated stream is not, and only
        the former may be cached.
        """
        begin, _ = block_bounds(first, block_size, size)
        _, end = block_bounds(last, block_size, size)
        resp = await self._download_uncached(message_id, begin, end)

        buffer = bytearray()
        index = first
        async for chunk in resp.chunks:
            buffer.extend(chunk)
            while index <= last:
                expected = block_length(index, block_size, size)
                if len(buffer) < expected:
                    break
                yield index, bytes(buffer[:expected]), True
                del buffer[:expected]
                index += 1

        if index <= last and buffer:
            yield index, bytes(buffer), False

    async def _cached_download(
        self, message_id: int, begin: int, end: int, size: int, block_size: int
    ) -> AsyncIterator[bytes]:
        """Serve ``[begin, end]`` from cached blocks, fetching what is missing.

        Missing blocks are fetched in runs rather than one at a time: a
        request per block would trade the round trips this cache is meant to
        save for a larger number of smaller ones.
        """
        cache = chunk_cache()
        blocks = block_range(begin, min(end, size - 1), block_size)

        index = blocks.start
        while index < blocks.stop:
            key = (self.private_file_channel, message_id, index)
            if (cached := cache.get(key)) is not None:
                yield self._slice(cached, index, block_size, begin, end)
                index += 1
                continue

            # Everything up to the next cached block is fetched in one go.
            run_end = index
            while run_end + 1 < blocks.stop and not cache.contains(
                (self.private_file_channel, message_id, run_end + 1)
            ):
                run_end += 1

            async for position, block, complete in self._fetch_blocks(
                message_id, index, run_end, size, block_size
            ):
                if complete:
                    cache.put(
                        (self.private_file_channel, message_id, position), block
                    )
                yield self._slice(block, position, block_size, begin, end)

            index = run_end + 1

    @staticmethod
    def _slice(
        block: bytes, index: int, block_size: int, begin: int, end: int
    ) -> bytes:
        """The part of one block that falls inside the requested range."""
        block_begin = index * block_size
        start = max(0, begin - block_begin)
        stop = min(len(block), end - block_begin + 1)
        return block[start:stop] if stop > start else b""

    async def _download_cached(
        self, message_id: int, begin: int, end: int
    ) -> Optional[DownloadFileResp]:
        """Wrap the download in the block cache, if it can be applied.

        Returns ``None`` when the cache cannot help -- disabled, or a
        message whose size is unknown -- so the caller falls through to the
        plain path.
        """
        cache = chunk_cache()
        if not cache.enabled or begin < 0:
            return None

        size = await self._document_size(message_id)
        if size is None or size <= 0 or begin >= size:
            return None

        if end < 0 or end > size - 1:
            end = size - 1
        if end < begin:
            return None

        block_size = _transfer().chunk_cache_block_bytes
        self._schedule_readahead(message_id, end // block_size, size, block_size)

        return DownloadFileResp(
            chunks=self._cached_download(message_id, begin, end, size, block_size),
            size=self._size(begin, end),
        )

    def _schedule_readahead(
        self, message_id: int, after_block: int, size: int, block_size: int
    ) -> None:
        """Pull the blocks just past this request into the cache.

        Readers rarely stop where they said they would: a player asks for a
        few kilobytes and comes back for the next few, and an SFTP client
        walks a whole file that way. Fetching the next blocks while the
        current ones are being served turns the following request into a
        cache hit.

        Deliberately best-effort -- capped, de-duplicated, and silent about
        failures, because nobody is waiting on it.
        """
        count = _transfer().chunk_cache_readahead
        if count < 1 or len(self.__readahead) >= MAX_READAHEAD_TASKS:
            return

        cache = chunk_cache()
        last_block = (size - 1) // block_size
        wanted = [
            index
            for index in range(after_block + 1, min(after_block + count, last_block) + 1)
            if not cache.contains((self.private_file_channel, message_id, index))
        ]
        if not wanted:
            return

        key = (message_id, wanted[0], wanted[-1])
        if key in self.__readahead:
            return
        self.__readahead.add(key)

        async def run() -> None:
            try:
                async for index, block, complete in self._fetch_blocks(
                    message_id, wanted[0], wanted[-1], size, block_size
                ):
                    if complete:
                        cache.put(
                            (self.private_file_channel, message_id, index), block
                        )
            except Exception as ex:
                logger.debug(f"Read-ahead for message {message_id} failed: {ex}")
            finally:
                self.__readahead.discard(key)

        asyncio.create_task(run())

    async def download_file(
        self, message_id: int, begin: int, end: int
    ) -> DownloadFileResp:
        if (cached := await self._download_cached(message_id, begin, end)) is not None:
            return cached
        return await self._download_uncached(message_id, begin, end)

    async def _download_uncached(
        self, message_id: int, begin: int, end: int
    ) -> DownloadFileResp:
        if (
            (account_config := get_config().telegram.account)
            and account_config.used_to_download
            and (account := self.tdlib.account)
        ):
            return await account.download_file(
                DownloadFileReq(
                    chat=self.private_file_channel,
                    message_id=message_id,
                    begin=begin,
                    end=end,
                )
            )

        if (
            end > 0
            and self._size(begin, end)
            > _transfer().parallel_download_threshold_bytes
        ):
            return await self.download_file_parallel(message_id, begin, end)

        return await self.tdlib.next_bot.download_file(
            DownloadFileReq(
                chat=self.private_file_channel,
                message_id=message_id,
                begin=begin,
                end=end,
            )
        )
