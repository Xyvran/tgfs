import asyncio
import logging
from dataclasses import dataclass
from functools import reduce
from typing import List, Optional, Set

from tgfs.reqres import GetMessagesReq, GetMessagesResp, MessageResp
from tgfs.telegram.interface import TDLibApi
from tgfs.utils.message_cache import channel_cache

# How long a batch collects further requests before it is sent. Counted from
# the *first* pending request, so a steady stream of requests cannot keep
# pushing the flush further out.
DELAY = 0.5


logger = logging.getLogger(__name__)


@dataclass
class Request:
    ids: list[int]
    future: asyncio.Future[GetMessagesResp]


class MessageBroker:
    def __init__(self, tdlib: TDLibApi, private_file_channel: int):
        self.tdlib = tdlib
        self.__requests: List[Request] = []
        self.__lock = asyncio.Lock()
        self.__task: Optional[asyncio.Task] = None
        self.private_file_channel = private_file_channel

    async def get_messages(self, ids: list[int]) -> list[Optional[MessageResp]]:
        if cached_messages := channel_cache(self.private_file_channel).id.gets(ids):
            if all(msg is not None for msg in cached_messages):
                return cached_messages

        loop = asyncio.get_running_loop()
        future = loop.create_future()

        async with self.__lock:
            self.__requests.append(Request(ids, future))
            if self.__task is None:
                self.__task = loop.create_task(self.__collect())
        return await future

    @property
    def __bots_count(self) -> int:
        """How many bot clients a failing request may be retried on.

        Taken from the live client list rather than the config: a
        deployment using the legacy single ``bot.token`` key has an empty
        ``bot.tokens`` list, which would leave the retry loop with nothing
        to iterate over.
        """
        return max(1, len(self.tdlib.bots))

    async def __collect(self) -> None:
        """Flush batches until a whole window passes with nothing pending.

        Keeping one collector alive across batches is what bounds the wait:
        requests that arrive while a batch is in flight join the next one
        instead of each restarting the timer.
        """
        in_flight: List[Request] = []
        try:
            while True:
                await asyncio.sleep(DELAY)
                async with self.__lock:
                    in_flight, self.__requests = self.__requests, []
                await self.process_requests(in_flight)
                in_flight = []
                async with self.__lock:
                    # Retire as soon as the queue runs dry rather than
                    # idling through another window: a request arriving
                    # later simply starts a fresh collector.
                    if not self.__requests:
                        self.__task = None
                        return
        except BaseException as ex:
            # Nobody else will ever complete these futures, so a collector
            # that dies -- cancelled at shutdown, or killed by an unexpected
            # error -- has to hand the failure to its waiters instead of
            # leaving them hanging. No await in between, so the swap needs
            # no lock.
            pending, self.__requests = self.__requests, []
            self.__task = None
            for request in (*in_flight, *pending):
                if not request.future.done():
                    request.future.set_exception(ex)
            raise

    async def process_requests(self, requests: List[Request]) -> None:
        if not requests:
            return

        ids: Set[int] = reduce(lambda full, req: full.union(req.ids), requests, set())

        e: Optional[Exception] = None
        bot = self.tdlib.next_bot
        for _ in range(self.__bots_count):
            try:

                messages = await bot.get_messages(
                    GetMessagesReq(
                        chat=self.private_file_channel, message_ids=tuple(ids)
                    )
                )

                messages_map = {
                    msg.message_id: msg for msg in messages if msg is not None
                }

                for r in requests:
                    if not r.future.done():
                        r.future.set_result(
                            [messages_map.get(msg_id) for msg_id in r.ids]
                        )
                return
            except Exception as ex:
                e = ex
                me = await bot.get_me()
                logger.error(
                    f"{me.name} failed to get messages: {ex}, retrying with next bot..."
                )
                bot = self.tdlib.next_bot
        if not e:
            return

        logger.error(
            "All bots failed to get messages, propagating exception to all requests."
        )
        for request in requests:
            if e and not request.future.done():
                request.future.set_exception(e)
