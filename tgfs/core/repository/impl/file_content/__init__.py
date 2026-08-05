import asyncio
import logging
from typing import Generator, List, Optional

from tgfs.core.api import MessageApi
from tgfs.core.mirror import MirrorGroup
from tgfs.core.model import TGFSFileVersion
from tgfs.core.repository.interface import IFileContentRepository
from tgfs.errors import TechnicalError
from tgfs.reqres import (
    EditMessageMediaReq,
    FileContent,
    FileMessageFromBuffer,
    SentFileMessage,
    UploadableFileMessage,
)
from tgfs.utils.chained_async_iterator import ChainedAsyncIterator

from .file_uploader import FileUploader

logger = logging.getLogger(__name__)
RETRY_INTERVAL = 5  # seconds

PART_SIZE_DEFAULT = (
    512 * 1024 * 4000
)  # 2 GB, max size of a single file message in Telegram
PART_SIZE_PREMIUM = (
    512 * 1024 * 8000
)  # 4 GB, max size of a single file message in Telegram Premium


class TGMsgFileContentRepository(IFileContentRepository):
    def __init__(
        self,
        message_api: MessageApi,
        use_account_api_to_upload: bool,
        mirror_group: Optional[MirrorGroup] = None,
    ):
        self._message_api = message_api
        self._use_account_api_to_upload = (
            use_account_api_to_upload and self._message_api.tdlib.account
        )
        self._mirror_group = mirror_group

    async def _send_file(
        self, file_msg: UploadableFileMessage, use_account_api: bool
    ) -> SentFileMessage:
        if use_account_api and (account_api := self._message_api.tdlib.account):
            api = account_api
        else:
            api = self._message_api.tdlib.next_bot

        uploader = FileUploader(api, file_msg)
        logger.info(
            f"Uploading file {file_msg.name} of size {file_msg.size} bytes to channel {self._message_api.private_file_channel} "
            f"using {(await api.get_me()).name}."
        )
        size = await uploader.upload()

        while True:
            try:
                message = await uploader.send(
                    self._message_api.private_file_channel,
                )
                return SentFileMessage(message_id=message.message_id, size=size)
            except Exception as ex:
                logger.error(
                    f"Exception occurred when sending file {file_msg.name}: {ex}. "
                    f"Waiting {RETRY_INTERVAL} seconds before retrying."
                )
                await asyncio.sleep(RETRY_INTERVAL)

    @staticmethod
    def _partition(size: int, part_size) -> Generator[int]:
        parts = (size + part_size - 1) // part_size
        for i in range(parts - 1):
            yield part_size
        yield size - (parts - 1) * part_size

    async def save(self, file_msg: UploadableFileMessage) -> List[SentFileMessage]:
        size = file_msg.get_size()

        res: List[SentFileMessage] = []
        file_name = file_msg.name or "unnamed"

        premium_upload = size > PART_SIZE_DEFAULT and self._use_account_api_to_upload

        for i, part_size in enumerate(
            self._partition(size, PART_SIZE_PREMIUM)
            if premium_upload
            else self._partition(size, PART_SIZE_DEFAULT)
        ):
            file_msg.name = f"[part{i+1}]{file_name}"
            file_msg.size = part_size
            res.append(
                await self._send_file(
                    file_msg, use_account_api=True if premium_upload else False
                )
            )
            file_msg.next_part(part_size)

        # Replicate the freshly uploaded parts into the mirror channels.
        # Server-side forwarding, so this costs one RPC per mirror, not a
        # second upload. The mapping travels back to the caller inside the
        # SentFileMessage objects and ends up in TGFSFileVersion.mirrors.
        if self._mirror_group:
            mirror_map = await self._mirror_group.mirror_parts(
                [m.message_id for m in res]
            )
            for channel_key, mirror_ids in mirror_map.items():
                for sent, mirror_id in zip(res, mirror_ids):
                    sent.mirrors[channel_key] = mirror_id
        return res

    async def update(self, message_id: int, buffer: bytes, name: str) -> int:
        file_msg: FileMessageFromBuffer = FileMessageFromBuffer.new(
            buffer=buffer,
            name=name,
        )

        uploader = FileUploader(self._message_api.tdlib.next_bot, file_msg)
        await uploader.upload()

        while True:
            try:
                message = await uploader.client.edit_message_media(
                    EditMessageMediaReq(
                        chat=self._message_api.private_file_channel,
                        message_id=message_id,
                        file=uploader.get_uploaded_file(),
                    )
                )
                return message.message_id
            except Exception as ex:
                logger.error(
                    f"Exception occurred when editing document of message {message_id}: {ex}. "
                    f"Waiting {RETRY_INTERVAL} seconds before retrying."
                )
                await asyncio.sleep(RETRY_INTERVAL)

    @staticmethod
    def _get_file_part_to_download(
        fv: TGFSFileVersion, begin: int, end: int
    ) -> Generator[tuple[int, int, int]]:
        for _, message_id, part_begin, part_end in (
            TGMsgFileContentRepository._get_file_parts_indexed(fv, begin, end)
        ):
            yield message_id, part_begin, part_end

    @staticmethod
    def _get_file_parts_indexed(
        fv: TGFSFileVersion, begin: int, end: int
    ) -> Generator[tuple[int, int, int, int]]:
        if fv.size <= 0:
            return
        if end < 0:
            end = fv.size
        if begin < 0:
            raise TechnicalError(
                f"Invalid begin value {begin} for file version {fv.id} with size {fv.size}"
            )
        if begin > end:
            raise TechnicalError(
                f"Invalid range: begin {begin} is greater than end {end} for file version {fv.id}"
            )
        if end > fv.size:
            raise TechnicalError(
                f"Invalid end value {end} for file version {fv.id} with size {fv.size}"
            )

        offset = 0
        i_part = 0

        while i_part < len(fv.part_sizes) and offset + fv.part_sizes[i_part] <= begin:
            offset += fv.part_sizes[i_part]
            i_part += 1

        if i_part >= len(fv.part_sizes):
            raise TechnicalError(
                f"Begin offset {begin} exceeds total file size {fv.size} for file version {fv.id}"
            )

        while i_part < len(fv.part_sizes) and offset < end:
            part_size = fv.part_sizes[i_part]
            part_begin = max(0, begin - offset)
            part_end = min(part_size, end - offset)
            if part_begin < part_end:
                yield i_part, fv.message_ids[i_part], part_begin, part_end
            offset += part_size
            i_part += 1

    def _part_sources(
        self, fv: TGFSFileVersion, part_idx: int, message_id: int
    ) -> List[tuple[Optional[str], int]]:
        """Download sources for one part: the primary plus every mirror
        channel that holds a copy. ``None`` denotes the primary channel.

        While the primary is marked dead (circuit breaker), mirrors are
        tried first so each read does not pay a doomed primary RPC; the
        primary stays in the list as the source of last resort.
        """
        sources: List[tuple[Optional[str], int]] = [(None, message_id)]
        if self._mirror_group:
            for channel_key, mirror_ids in (fv.mirrors or {}).items():
                if (
                    self._mirror_group.api_for(channel_key)
                    and part_idx < len(mirror_ids)
                    and mirror_ids[part_idx] > 0
                ):
                    sources.append((channel_key, mirror_ids[part_idx]))
            if self._mirror_group.primary_dead() and len(sources) > 1:
                sources = sources[1:] + sources[:1]
        return sources

    async def _download_part(
        self, fv: TGFSFileVersion, part_idx: int, message_id: int, begin: int, end: int
    ):
        """Stream one part, failing over to mirror copies on error.

        Failover also works mid-stream: bytes already delivered are
        skipped by advancing ``begin`` before retrying the next source.
        """
        sources = self._part_sources(fv, part_idx, message_id)
        served = 0
        last_ex: Optional[Exception] = None
        for channel_key, mid in sources:
            api = (
                self._message_api
                if channel_key is None
                else self._mirror_group.api_for(channel_key)  # type: ignore[union-attr]
            )
            if api is None:
                continue
            try:
                resp = await api.download_file(mid, begin + served, end)
                async for chunk in resp.chunks:
                    yield chunk
                    served += len(chunk)
                return
            except Exception as ex:
                last_ex = ex
                if channel_key is None and self._mirror_group:
                    self._mirror_group.mark_primary_dead()
                if len(sources) > 1:
                    logger.warning(
                        f"Downloading part {part_idx} (message {mid}) from "
                        f"{'primary' if channel_key is None else f'mirror {channel_key}'} "
                        f"failed: {ex}. Trying next source."
                    )
        if last_ex:
            raise last_ex
        raise TechnicalError(
            f"No download source available for part {part_idx} of {fv.id}"
        )

    async def get(
        self, fv: TGFSFileVersion, begin: int, end: int, name: str
    ) -> FileContent:
        logger.info(f"Retrieving file content for {name}@{fv.id} from {begin} to {end}")

        parts = [
            self._download_part(fv, part_idx, message_id, part_begin, part_end)
            for part_idx, message_id, part_begin, part_end in (
                self._get_file_parts_indexed(fv, begin, end)
            )
        ]
        return ChainedAsyncIterator(parts)
