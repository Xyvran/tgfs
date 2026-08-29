import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from telethon.helpers import generate_random_long

from tgfs.config import get_config
from tgfs.errors import TechnicalError
from tgfs.reqres import (
    SaveBigFilePartReq,
    SaveFilePartReq,
    SendFileReq,
    SendMessageResp,
    UploadableFileMessage,
    UploadedFile,
)
from tgfs.telegram.interface import ITDLibClient
from tgfs.utils.others import flood_wait_seconds, is_big_file

logger = logging.getLogger(__name__)

# A part that keeps failing has to give up eventually: the old unbounded,
# sleepless retry turned one broken part into a busy loop against Telegram,
# which is how a slow upload becomes a rate-limited one.
MAX_PART_ATTEMPTS = 5
RETRY_BASE_DELAY = 0.5
RETRY_MAX_DELAY = 30.0


@dataclass
class WorkersConfig:
    small: int = 3
    big: int = 8

    @classmethod
    def from_config(cls) -> "WorkersConfig":
        transfer = get_config().tgfs.transfer
        return cls(
            small=transfer.upload_workers_small, big=transfer.upload_workers_big
        )


@dataclass
class FileChunk:
    content: bytes
    file_part: int


class FileUploader:
    def __init__(
        self,
        client: ITDLibClient,
        file_msg: UploadableFileMessage,
        workers: Optional[WorkersConfig] = None,
    ):
        self.client = client
        self._file_msg = file_msg
        self._file_size = self._file_msg.get_size()
        self._file_name = self._file_msg.file_name()

        # One part size for every file. The library's heuristic drops to
        # 128 KiB below 100 MB, which quadruples the number of requests for
        # no gain -- 512 KiB is accepted for any size.
        self._chunk_size = get_config().tgfs.transfer.upload_part_size_bytes
        self._total_parts = (self._file_size + self._chunk_size - 1) // self._chunk_size

        self._part_indexes: asyncio.Queue[int] = asyncio.Queue(
            maxsize=self._total_parts
        )

        self._workers = workers or WorkersConfig.from_config()

        self._file_id = generate_random_long()

        self._is_big = is_big_file(self._file_size)
        self._read_size = 0
        self._uploaded_size = 0

        self._num_workers = self._workers.big if self._is_big else self._workers.small
        self._lock = asyncio.Lock()

    async def _close(self) -> None:
        await self._file_msg.close()

    async def _read(self, length: int) -> bytes:
        return await self._file_msg.read(length)

    async def _upload_chunk(self, chunk: FileChunk) -> None:
        for attempt in range(1, MAX_PART_ATTEMPTS + 1):
            try:
                if self._is_big:
                    rsp = await self.client.save_big_file_part(
                        SaveBigFilePartReq(
                            file_id=self._file_id,
                            bytes=chunk.content,
                            file_part=chunk.file_part,
                            file_total_parts=self._total_parts,
                        )
                    )
                else:
                    rsp = await self.client.save_file_part(
                        SaveFilePartReq(
                            file_id=self._file_id,
                            bytes=chunk.content,
                            file_part=chunk.file_part,
                        )
                    )

                if not rsp.success:
                    raise TechnicalError(f"Unexpected response: {rsp}")

                self._uploaded_size += len(chunk.content)
                return

            except Exception as e:
                if attempt == MAX_PART_ATTEMPTS:
                    logger.error(
                        f"Giving up on part {chunk.file_part} for {self._file_name} "
                        f"after {attempt} attempts: {e}"
                    )
                    raise

                if (wait := flood_wait_seconds(e)) is not None:
                    delay = float(wait)
                else:
                    delay = min(
                        RETRY_BASE_DELAY * 2 ** (attempt - 1), RETRY_MAX_DELAY
                    )

                logger.warning(
                    f"Error uploading part {chunk.file_part} for {self._file_name}: "
                    f"{e}, attempt={attempt}/{MAX_PART_ATTEMPTS}, "
                    f"retrying in {delay:.1f}s"
                )
                await asyncio.sleep(delay)

    def _done_reading(self) -> bool:
        return self._read_size >= self._file_size

    async def _upload_next_part(self, part: int) -> int:
        async with self._lock:
            if self._done_reading():
                return 0
            size_to_read = min(self._file_size - self._read_size, self._chunk_size)
            content = await self._read(size_to_read)
            self._read_size += size_to_read

        await self._upload_chunk(FileChunk(content=content, file_part=part))
        return size_to_read

    async def _cancelled(self) -> bool:
        if tt := self._file_msg.task_tracker:
            return await tt.cancelled()
        return False

    async def upload(self) -> int:
        await self._file_msg.open()

        for i in range(self._total_parts):
            await self._part_indexes.put(i)

        async def create_worker(worker_id: int) -> bool:
            while True:
                if await self._cancelled():
                    logger.warning(
                        f"Task uploading for {self._file_name} was cancelled. Worker {worker_id} exiting."
                    )
                    return False

                try:
                    part_size = await self._upload_next_part(
                        self._part_indexes.get_nowait()
                    )
                except asyncio.QueueEmpty:
                    logger.debug(
                        f"[Worker {worker_id}] No more parts to upload for {self._file_name}. Worker exiting."
                    )
                    return True
                logger.debug(
                    f"[Worker {worker_id}] {self._uploaded_size * 100 / self._file_size}% uploaded. file_id={self._file_id} file_name={self._file_name}"
                )
                if (tt := self._file_msg.task_tracker) and part_size > 0:
                    await tt.update_progress(size_delta=part_size)

        workers = [
            asyncio.create_task(create_worker(worker_id))
            for worker_id in range(self._num_workers)
        ]
        try:
            await asyncio.gather(*workers)
        except Exception:
            # One dead part makes the whole file_id unusable, so the other
            # workers should stop feeding it instead of uploading into a
            # file that can never be sent.
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            raise

        await self._close()
        return self._file_size

    def get_uploaded_file(self) -> UploadedFile:
        return UploadedFile(
            id=self._file_id,
            parts=self._total_parts,
            name=self._file_name,
        )

    async def send(self, chat_id: int, caption: str = "") -> SendMessageResp:
        logger.debug(
            f"Sending file {self._file_name} ({self._file_id}) to chat {chat_id}"
        )

        req = SendFileReq(
            chat=chat_id,
            file=self.get_uploaded_file(),
            name=self._file_name,
            caption=caption,
        )

        if self._is_big:
            return await self.client.send_big_file(req)
        return await self.client.send_small_file(req)
