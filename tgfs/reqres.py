
import asyncio
import os
from dataclasses import dataclass, field
from io import IOBase
from typing import AsyncIterator, Dict, Optional, Tuple, List

from tgfs.tasks.integrations import TaskTracker


@dataclass
class Message:
    message_id: int


@dataclass
class SentFileMessage(Message):
    size: int
    # Message ids of copies of this part in mirror channels, keyed by the
    # mirror channel id as configured (string). Empty when redundancy is off.
    mirrors: Dict[str, int] = field(default_factory=dict)


@dataclass
class Chat:
    chat: int


@dataclass
class GetMessagesReq(Chat):
    message_ids: Tuple[int, ...]


@dataclass
class Document:
    size: int
    id: int
    access_hash: int
    file_reference: bytes
    mime_type: Optional[str]


@dataclass
class MessageResp(Message):
    text: str
    document: Optional[Document]


@dataclass
class MessageRespWithDocument(MessageResp):
    document: Document


GetMessagesResp = list[Optional[MessageResp]]
GetMessagesRespNoNone = list[MessageResp]


@dataclass
class SearchMessageReq(Chat):
    search: str


@dataclass
class ForwardMessagesReq:
    from_chat: int
    to_chat: int
    message_ids: Tuple[int, ...]


@dataclass
class DeleteMessagesReq(Chat):
    message_ids: Tuple[int, ...]


GetPinnedMessageReq = Chat
SendMessageResp = Message


@dataclass
class SendTextReq(Chat):
    text: str


@dataclass
class EditMessageTextReq(SendTextReq, Message):
    pass


@dataclass
class PinMessageReq(Chat, Message):
    pass


@dataclass
class SaveFilePartReq:
    file_id: int
    bytes: bytes
    file_part: int


@dataclass
class SaveBigFilePartReq(SaveFilePartReq):
    file_total_parts: int


@dataclass
class SaveFilePartResp:
    success: bool


@dataclass
class UploadedFile:
    id: int
    parts: int
    name: str


@dataclass
class FileAttr:
    name: str
    caption: str


@dataclass
class SendFileReq(Chat, FileAttr):
    file: UploadedFile


@dataclass
class EditMessageMediaReq(Chat, Message):
    file: UploadedFile


@dataclass
class DownloadFileReq(Chat, Message):
    begin: int
    end: int


FileContent = AsyncIterator[bytes]


@dataclass
class DownloadFileResp:
    chunks: FileContent
    size: int


@dataclass
class GetMeResp:
    is_premium: bool
    name: str


@dataclass
class FileTags:
    pass


@dataclass
class FileMessage:
    name: str
    size: int


@dataclass
class UploadableFileMessage(FileMessage):
    caption: str
    tags: FileTags
    _offset: int
    _read_size: int
    
    task_tracker: Optional[TaskTracker]

    def _get_size(self) -> int:
        return 0

    def get_size(self) -> int:
        return self.size or self._get_size()

    async def open(self) -> None:
        pass

    async def read(self, length: int) -> bytes:
        raise NotImplementedError("Subclasses must implement the read method")

    async def close(self) -> None:
        pass

    def file_name(self) -> str:
        return self.name or "unnamed"

    def next_part(self, part_size: int) -> None:
        self._offset += part_size
        self._read_size = 0


@dataclass
class UploadableFileMessageStreaming(UploadableFileMessage):
    """
    Streaming upload that can handle unknown-size files.
    
    The main difference from UploadableFileMessage is that a streaming message doesn't
    know its size at creation time, and parts are uploaded individually without 
    requiring total file size upfront.
    """  
    # For partial reads to maintain state
    _pending_data: bytearray = field(default_factory=bytearray)
    
    def __post_init__(self):
        # Initialize the base class properly for streaming use case
        if self.size is None:
            self.size = 0

    async def read(self, length: int) -> bytes:
        """
        Read from pending data and handle reading from stream.
        This method should be overridden by streaming implementations.
        """
        raise NotImplementedError("Subclasses must implement the read method")
        
    @classmethod
    def new(cls, name: str = "unnamed") -> "UploadableFileMessageStreaming":
        return cls(
            name=name,
            caption="",
            tags=FileTags(),
            _offset=0,
            size=0,
            task_tracker=None,
            _read_size=0,
            _pending_data=bytearray()
        )


@dataclass
class StreamingPartInfo:
    """Information about a single uploaded part for streaming."""
    message_id: int
    size: int


class StreamingUploadManager:
    """Manages a streaming upload session and tracks individual parts"""
    
    def __init__(self, part_size_bytes: int = 512 * 1024 * 1024):  # Default 512MB
        self.parts: List[StreamingPartInfo] = []
        self.pending_parts: List[int] = []  # message IDs of upload jobs in-flight
        self.total_size: int = 0
        self._part_size_bytes = part_size_bytes 
        self._current_part_buffer: bytearray = bytearray()
        self._buffered_part_size: int = 0  # Size of the part currently being buffered
        
    def add_part(self, message_id: int, size: int) -> None:
        """Add uploaded part metadata"""
        self.parts.append(StreamingPartInfo(message_id=message_id, size=size))
        self.total_size += size
     
    def remove_part(self, message_id: int) -> bool:
        """Remove a single part by message_id if exists"""
        for i, part in enumerate(self.parts):
            if part.message_id == message_id:
                self.parts.pop(i)
                self.total_size -= part.size
                return True
        return False
        
    @property
    def part_count(self) -> int:
        """Get the count of uploaded parts"""
        return len(self.parts)
        
    def get_parts_with_sizes(self) -> List[Tuple[int, int]]:
        """Get list of (message_id, size) tuples"""
        return [(part.message_id, part.size) for part in self.parts]


@dataclass
class FileMessageEmpty(FileMessage):
    @classmethod
    def new(cls, name: str = "unnamed") -> "FileMessageEmpty":
        return cls(name=name, size=0)


@dataclass
class FileMessageFromPath(UploadableFileMessage):
    path: str
    _fd: IOBase

    def _get_size(self) -> int:
        return os.path.getsize(self.path)

    @classmethod
    def new(cls, path: str, name: str = "unnamed") -> "FileMessageFromPath":
        return cls(
            name=name,
            caption="",
            tags=FileTags(),
            path=path,
            _offset=0,
            size=os.path.getsize(path),
            task_tracker=None,
            _read_size=0,
            _fd=open(path, "rb"),
        )

    async def read(self, length: int) -> bytes:
        # Off the event loop: a blocking disk read here stalls every other
        # transfer in the process, not just this one.
        return await asyncio.to_thread(self._fd.read, length)

    async def close(self) -> None:
        if self._fd:
            self._fd.close()

    def file_name(self) -> str:
        return self.name or os.path.basename(self.path)


@dataclass
class FileMessageFromBuffer(UploadableFileMessage):
    buffer: bytes
    __buffer: bytes = b""

    def _get_size(self) -> int:
        return len(self.buffer)

    @classmethod
    def new(cls, buffer: bytes, name: str = "unnamed") -> "FileMessageFromBuffer":
        return cls(
            name=name,
            caption="",
            tags=FileTags(),
            buffer=buffer,
            _offset=0,
            size=len(buffer),
            task_tracker=None,
            _read_size=0,
        )

    async def open(self) -> None:
        self.__buffer = self.buffer[self._offset :]

    async def read(self, length: int) -> bytes:
        chunk = self.__buffer[:length]
        self.__buffer = self.__buffer[length:]
        return chunk


@dataclass
class FileMessageFromStream(UploadableFileMessage):
    stream: FileContent
    buffer: bytearray = field(default_factory=bytearray)

    @classmethod
    def new(
        cls,
        stream: FileContent,
        size: int,
        name: str = "unnamed",
    ) -> "FileMessageFromStream":
        return cls(
            name=name,
            caption="",
            tags=FileTags(),
            stream=stream,
            _offset=0,
            size=size,
            task_tracker=None,
            _read_size=0,
        )

    async def read(self, length: int) -> bytes:
        """Take ``length`` bytes off the front of the stream.

        Kept in one buffer rather than a list of chunks: rejoining the list
        on every read copies everything still pending, which for a stream
        arriving in small chunks is quadratic in the size of the part.
        """
        size_to_return = min(length, self.get_size() - self._read_size)
        while len(self.buffer) < size_to_return:
            self.buffer.extend(await anext(self.stream))

        res = bytes(self.buffer[:size_to_return])
        del self.buffer[:size_to_return]
        self._read_size += size_to_return
        return res

    def file_name(self) -> str:
        return self.name or "unnamed"


@dataclass
class FileMessageImported(FileMessage):
    message_id: int

    @classmethod
    def new(
        cls, message_id: int, size: int, name: str = "unnamed"
    ) -> "FileMessageImported":
        return cls(name=name, size=size, message_id=message_id)
