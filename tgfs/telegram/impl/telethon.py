import asyncio
import logging
import os
from itertools import cycle
from typing import List, Optional, Sequence

from telethon import TelegramClient
from telethon import functions as tlf
from telethon import types as tlt
from telethon.errors import FileReferenceExpiredError, SessionPasswordNeededError
from telethon.helpers import TotalList
from telethon.sessions import StringSession
from telethon.tl.types import InputDocumentFileLocation, PeerChannel

from tgfs.config import Config, get_config
from tgfs.errors import TechnicalError, UnDownloadableMessage
from tgfs.reqres import (
    DeleteMessagesReq,
    Document,
    DownloadFileReq,
    DownloadFileResp,
    EditMessageMediaReq,
    EditMessageTextReq,
    ForwardMessagesReq,
    GetMeResp,
    GetMessagesReq,
    GetMessagesResp,
    GetMessagesRespNoNone,
    GetPinnedMessageReq,
    Message,
    MessageResp,
    PinMessageReq,
    SaveBigFilePartReq,
    SaveFilePartReq,
    SaveFilePartResp,
    SearchMessageReq,
    SendFileReq,
    SendMessageResp,
    SendTextReq,
)
from tgfs.telegram.interface import ITDLibClient
from tgfs.utils.chunk_cache import chunk_cache
from tgfs.utils.message_cache import channel_cache
from tgfs.utils.others import exclude_none

logger = logging.getLogger(__name__)


class TelethonAPI(ITDLibClient):
    def __init__(
        self,
        client: TelegramClient,
        extra_connections: Sequence[TelegramClient] = (),
    ):
        super().__init__()
        self._client = client
        # One MTProto connection carries its requests one after another, so
        # the file-part calls -- and only those -- are spread over every
        # connection this session has. Metadata calls stay on the primary
        # one, where the message cache and the session state live.
        self._transfer_clients: List[TelegramClient] = [client, *extra_connections]
        self.__transfer_cycle = cycle(self._transfer_clients)

    @property
    def _transfer_client(self) -> TelegramClient:
        return next(self.__transfer_cycle)

    async def __get_messages(self, *args, **kwargs) -> Sequence[tlt.Message]:
        messages = await self._client.get_messages(*args, **kwargs)
        if not isinstance(messages, TotalList):
            raise TechnicalError("Unexpected response type from get_messages")
        return messages

    @staticmethod
    def _transform_messages(
        messages: Sequence[Optional[tlt.Message]],
    ) -> GetMessagesResp:
        res = GetMessagesResp()

        for m in messages:
            if not m:
                res.append(None)
                continue

            obj = MessageResp(
                message_id=m.id,
                text="",
                document=None,
            )

            if m.message:
                obj.text = m.message

            if (
                isinstance(m.media, tlt.MessageMediaDocument)
                and (doc := m.media.document)
                and not isinstance(doc, tlt.DocumentEmpty)
            ):
                obj.document = Document(
                    size=doc.size,
                    id=doc.id,
                    access_hash=doc.access_hash,
                    file_reference=doc.file_reference,
                    mime_type=doc.mime_type,
                )

            res.append(obj)
        return res

    async def get_messages(self, req: GetMessagesReq) -> GetMessagesResp:
        cache = channel_cache(req.chat).id
        if message_id_to_fetch := cache.find_nonexistent(req.message_ids):
            fetched_messages = await self.__get_messages(
                entity=PeerChannel(channel_id=req.chat), ids=message_id_to_fetch
            )

            for message in exclude_none(self._transform_messages(fetched_messages)):
                cache[message.message_id] = message

        return GetMessagesResp(cache.gets(req.message_ids))

    async def send_text(self, req: SendTextReq) -> SendMessageResp:
        message = await self._client.send_message(
            entity=PeerChannel(channel_id=req.chat), message=req.text
        )
        return SendMessageResp(message_id=message.id)

    async def edit_message_text(self, req: EditMessageTextReq) -> SendMessageResp:
        channel_cache(req.chat).id[req.message_id] = None
        chunk_cache().invalidate(req.chat, req.message_id)
        message = await self._client.edit_message(
            entity=PeerChannel(channel_id=req.chat),
            message=req.message_id,
            text=req.text,
        )
        return SendMessageResp(message_id=message.id)

    async def edit_message_media(self, req: EditMessageMediaReq) -> Message:
        channel_cache(req.chat).id[req.message_id] = None
        chunk_cache().invalidate(req.chat, req.message_id)
        message = await self._client.edit_message(
            entity=PeerChannel(channel_id=req.chat),
            message=req.message_id,
            file=tlt.InputFile(
                id=req.file.id,
                parts=req.file.parts,
                name=req.file.name,
                md5_checksum="",
            ),
        )
        return Message(message_id=message.id)

    async def search_messages(self, req: SearchMessageReq) -> GetMessagesRespNoNone:
        cache = channel_cache(req.chat).search
        if req.search not in cache:
            messages = await self.__get_messages(
                entity=PeerChannel(channel_id=req.chat), search=req.search
            )
            cache[req.search] = tuple(exclude_none(self._transform_messages(messages)))
        return GetMessagesRespNoNone(cache[req.search])

    async def get_pinned_messages(
        self, req: GetPinnedMessageReq
    ) -> GetMessagesRespNoNone:
        return GetMessagesRespNoNone(
            list(
                exclude_none(
                    self._transform_messages(
                        await self.__get_messages(
                            entity=PeerChannel(channel_id=req.chat),
                            filter=tlt.InputMessagesFilterPinned(),
                        )
                    )
                )
            )
        )

    async def pin_message(self, req: PinMessageReq) -> None:
        await self._client.pin_message(
            entity=PeerChannel(channel_id=req.chat),
            message=req.message_id,
            notify=False,
        )

    async def save_big_file_part(self, req: SaveBigFilePartReq) -> SaveFilePartResp:
        success = await self._transfer_client(
            tlf.upload.SaveBigFilePartRequest(
                file_id=req.file_id,
                file_part=req.file_part,
                bytes=req.bytes,
                file_total_parts=req.file_total_parts,
            )
        )
        return SaveFilePartResp(success=success)

    async def save_file_part(self, req: SaveFilePartReq) -> SaveFilePartResp:
        success = await self._transfer_client(
            tlf.upload.SaveFilePartRequest(
                file_id=req.file_id,
                file_part=req.file_part,
                bytes=req.bytes,
            )
        )
        return SaveFilePartResp(success=success)

    async def send_big_file(self, req: SendFileReq) -> SendMessageResp:
        file = tlt.InputFileBig(
            id=req.file.id,
            parts=req.file.parts,
            name=req.file.name,
        )
        message = await self._client.send_file(
            entity=PeerChannel(channel_id=req.chat),
            file=file,
            caption=req.caption,
            force_document=True,
        )
        if not isinstance(message, tlt.Message):
            raise TechnicalError("Unexpected response type from send_file")
        return SendMessageResp(message_id=message.id)

    async def send_small_file(self, req: SendFileReq) -> SendMessageResp:
        file = tlt.InputFile(
            id=req.file.id,
            parts=req.file.parts,
            name=req.file.name,
            md5_checksum="",
        )
        message = await self._client.send_file(
            entity=PeerChannel(channel_id=req.chat),
            file=file,
            caption=req.caption,
            force_document=True,
        )
        if not isinstance(message, tlt.Message):
            raise TechnicalError("Unexpected response type from send_file")
        return SendMessageResp(message_id=message.id)

    async def forward_messages(
        self, req: ForwardMessagesReq
    ) -> list[SendMessageResp]:
        forwarded = await self._client.forward_messages(
            entity=PeerChannel(channel_id=req.to_chat),
            messages=list(req.message_ids),
            from_peer=PeerChannel(channel_id=req.from_chat),
        )
        if isinstance(forwarded, tlt.Message):
            forwarded = [forwarded]
        if len(forwarded) != len(req.message_ids) or any(
            m is None for m in forwarded
        ):
            raise TechnicalError(
                f"Forwarding {len(req.message_ids)} messages from {req.from_chat} "
                f"to {req.to_chat} returned {len(forwarded)} messages"
            )
        return [SendMessageResp(message_id=m.id) for m in forwarded]

    async def _document_for(
        self, chat: int, message_id: int, refresh: bool = False
    ) -> Document:
        """Resolve the document of a file message through the message cache.

        A range request only needs the document's id, access hash and file
        reference, so resolving the message again for every request costs a
        round trip that the cache already paid for. ``refresh`` drops the
        cached entry first, which is how an expired file reference is
        recovered -- Telegram lets those go stale, and the cached copy would
        otherwise keep failing.
        """
        if refresh:
            channel_cache(chat).id[message_id] = None

        messages = await self.get_messages(
            GetMessagesReq(chat=chat, message_ids=(message_id,))
        )

        if not (message := messages[0]) or not message.document:
            raise UnDownloadableMessage(message_id)
        return message.document

    async def download_file(self, req: DownloadFileReq) -> DownloadFileResp:
        document = await self._document_for(req.chat, req.message_id)

        chunk_size = req.chunk_size * 1024

        bytes_to_read = req.end - req.begin + 1

        async def chunks():
            rest = bytes_to_read

            if req.end < req.begin:
                raise TechnicalError(
                    f"Invalid range: end must be greater than or equal to begin, got begin={req.begin} end={req.end}"
                )

            doc = document
            offset = req.begin
            refreshed = False

            while rest > 0:
                try:
                    async for chunk in self._transfer_client.iter_download(
                        file=InputDocumentFileLocation(
                            id=doc.id,
                            access_hash=doc.access_hash,
                            file_reference=doc.file_reference,
                            thumb_size="",
                        ),
                        chunk_size=chunk_size,
                        offset=offset,
                    ):
                        if len(chunk) > rest:
                            chunk = chunk[:rest]
                        yield chunk
                        rest -= len(chunk)
                        offset += len(chunk)
                        if rest <= 0:
                            break
                except FileReferenceExpiredError:
                    # Re-resolve once and resume where the stream stopped.
                    if refreshed:
                        raise
                    refreshed = True
                    doc = await self._document_for(
                        req.chat, req.message_id, refresh=True
                    )
                    continue
                break

        return DownloadFileResp(chunks=chunks(), size=bytes_to_read)

    async def delete_messages(self, req: DeleteMessagesReq) -> None:
        if not req.message_ids:
            return
        cache = channel_cache(req.chat).id
        for mid in req.message_ids:
            cache[mid] = None
            chunk_cache().invalidate(req.chat, mid)
        await self._client.delete_messages(
            entity=PeerChannel(channel_id=req.chat),
            message_ids=list(req.message_ids),
        )

    async def resolve_channel_id(self, channel_id: str) -> int:
        try:
            return int(channel_id)
        except ValueError:
            entity = await self._client.get_entity(f"@{channel_id}")
            if not isinstance(entity, tlt.Channel):
                raise TechnicalError("Expected a Telegram channel")
            return entity.id

    async def _get_me(self) -> GetMeResp:
        me = await self._client.get_me()
        if not isinstance(me, tlt.User):
            raise TechnicalError("Expected a Telegram user")
        return GetMeResp(
            name=(
                f"@{me.username}"
                if me.username
                else f"{me.first_name} {me.last_name or ''}".strip()
            ),
            is_premium=bool(me.premium),
        )


class Session:
    def __init__(self, session_file: str):
        self.session_file = session_file

    def get(self) -> Optional[StringSession]:
        if os.path.exists(self.session_file):
            with open(self.session_file, "r") as f:
                return StringSession(f.read().strip())
        return None

    def save_multibot(self, session_string: str):
        dir_ = os.path.dirname(self.session_file)
        if os.path.isfile(dir_):
            raise Exception(
                f"{dir_} is a session file which only supports one bot session. "
                f"Please remove the file to upgrade to multi-bot version."
            )
        os.makedirs(dir_, exist_ok=True)
        with open(self.session_file, "w") as f:
            f.write(session_string)

    def save(self, session_string: str):
        if not os.path.exists(self.session_file):
            dir_ = os.path.dirname(self.session_file)
            os.makedirs(dir_, exist_ok=True)
        with open(self.session_file, "w") as f:
            f.write(session_string)


async def open_extra_connections(
    config: Config, client: TelegramClient
) -> List[TelegramClient]:
    """Open the additional connections ``connection_pool_size`` asks for.

    Telegram accepts several simultaneous connections per authorization,
    and a single connection sends its requests one at a time -- so this is
    what lets one bot transfer more than one part at a time. A connection
    that cannot be opened is not fatal: the session simply keeps the ones
    it got, which is the same behaviour as a pool size of one.
    """
    extra = get_config().tgfs.transfer.connection_pool_size - 1
    if extra < 1:
        return []

    session_string = client.session.save()  # type: ignore[attr-defined]
    connections: List[TelegramClient] = []
    for i in range(extra):
        try:
            connection = TelegramClient(
                StringSession(session_string), config.telegram.api_id, config.telegram.api_hash
            )
            await connection.connect()
            connections.append(connection)
        except Exception as ex:
            logger.warning(
                f"Could not open connection {i + 2} of {extra + 1} for this "
                f"session ({ex}); continuing with {len(connections) + 1}"
            )
            break

    if connections:
        logger.info(f"Opened {len(connections) + 1} connections for this session")
    return connections


async def login_as_account(config: Config) -> TelegramClient:
    if not config.telegram.account:
        raise TechnicalError("Account configuration is missing")

    api_id = config.telegram.api_id
    api_hash = config.telegram.api_hash

    session = Session(config.telegram.account.session_file)
    if sess := session.get():
        client = TelegramClient(sess, api_id, api_hash)
        await client.connect()
    else:
        client = TelegramClient(StringSession(), api_id, api_hash)
        await client.connect()

        phone_number = input("Phone number (with country code): ")
        sms_req = await client.send_code_request(phone_number, force_sms=False)
        code = input("Enter the code you received: ")

        try:
            await client.sign_in(
                phone=phone_number, code=code, phone_code_hash=sms_req.phone_code_hash
            )
        except SessionPasswordNeededError:
            password = input("Enter the 2FA password: ")
            await client.sign_in(password=password)
        except Exception as e:
            logger.error(f"Failed to sign in: {e}")
            raise
        session.save(client.session.save())  # type: ignore

    if (me := await client.get_me()) and isinstance(me, tlt.User) and me.username:
        logger.info(f"logged in as @{me.username}")
    else:
        logger.warning("logged in as account, but no username found")

    return client


async def login_as_bots(config: Config) -> List[TelegramClient]:
    api_id = config.telegram.api_id
    api_hash = config.telegram.api_hash

    bot_tokens = config.telegram.bot.tokens or [config.telegram.bot.token]

    async def login(token: str) -> TelegramClient:
        bot_id, _ = token.split(":")

        session = Session(
            os.path.join(config.telegram.bot.session_file, f"{bot_id}.session")
        )

        if sess := session.get():
            client = TelegramClient(sess, api_id, api_hash)
            await client.connect()
        else:
            client = TelegramClient(StringSession(), api_id, api_hash)
            await client.connect()
            await client.start(bot_token=token)  # type: ignore
            session.save_multibot(client.session.save())  # type: ignore

        if (me := await client.get_me()) and isinstance(me, tlt.User) and me.username:
            logger.info(f"logged in as @{me.username}")
        else:
            logger.warning("logged in as bot, but no username found")

        return client

    return await asyncio.gather(*(login(token) for token in bot_tokens))
