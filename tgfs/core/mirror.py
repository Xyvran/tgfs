"""Channel redundancy: RAID-1-style mirroring of file channels.

A :class:`MirrorGroup` binds the primary channel's :class:`MessageApi`
to one ``MessageApi`` per mirror channel and provides the write-side
primitives used by the repositories:

* ``mirror_parts`` copies content part messages into every mirror
  channel -- server-side via ``forward_messages`` (no re-upload
  bandwidth) or, in ``reupload`` mode, by streaming the part down from
  the primary and uploading it again (for channels where forwarding is
  restricted).
* ``mirror_fd`` keeps a copy of a file descriptor (JSON text message)
  in each mirror channel. Descriptors are *sent* rather than forwarded
  because a forwarded message cannot be edited later, and descriptors
  are edited on every new file version.
* ``mirror_pinned`` maintains a copy of the pinned metadata document.
* ``delete`` fans message deletion out to the mirror channels.

Failure policy: with ``strict=False`` (default) a failing mirror write
is logged and the affected channel is simply omitted from the result --
the primary write has already succeeded and the backfill task can close
the gap later. With ``strict=True`` the error propagates.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional

from tgfs.errors import MessageNotFound, TechnicalError

if TYPE_CHECKING:
    # Type-only import: tgfs.core.api imports modules that import this
    # one, so a runtime import would be circular.
    from tgfs.core.api import MessageApi

logger = logging.getLogger(__name__)

# How long reads prefer the mirrors after a primary-channel failure.
PRIMARY_DEAD_SECONDS = 60.0


@dataclass
class MirrorChannel:
    # Channel id exactly as written in the config -- this is the key
    # used in the serialized metadata, NOT the lib-specific resolved id.
    key: str
    message_api: "MessageApi"


class MirrorGroup:
    def __init__(
        self,
        primary: "MessageApi",
        channels: List[MirrorChannel],
        mode: str = "forward",
        strict: bool = False,
    ):
        self._primary = primary
        self._channels = channels
        self._mode = mode
        self._strict = strict
        self._by_key = {ch.key: ch for ch in channels}
        self._primary_dead_until = 0.0

    @property
    def channel_keys(self) -> List[str]:
        return [ch.key for ch in self._channels]

    def api_for(self, key: str) -> Optional["MessageApi"]:
        ch = self._by_key.get(key)
        return ch.message_api if ch else None

    # -- primary health (read-path circuit breaker) ------------------------

    def mark_primary_dead(self) -> None:
        self._primary_dead_until = time.monotonic() + PRIMARY_DEAD_SECONDS

    def primary_dead(self) -> bool:
        return time.monotonic() < self._primary_dead_until

    # -- content parts -----------------------------------------------------

    def missing_channels(
        self, mirrors: Dict[str, List[int]], n_parts: int
    ) -> List[str]:
        """Mirror channels for which a version has no complete copy."""
        res = []
        for key in self.channel_keys:
            ids = mirrors.get(key)
            if not ids or len(ids) != n_parts or any(mid <= 0 for mid in ids):
                res.append(key)
        return res

    async def mirror_parts(
        self,
        message_ids: List[int],
        only_channels: Optional[List[str]] = None,
    ) -> Dict[str, List[int]]:
        """Copy the given primary part messages into the mirror channels.

        Returns ``{channel_key: [mirror message ids]}`` for every channel
        that succeeded, aligned with ``message_ids``.
        """
        res: Dict[str, List[int]] = {}
        for ch in self._channels:
            if only_channels is not None and ch.key not in only_channels:
                continue
            try:
                if self._mode == "reupload":
                    res[ch.key] = [
                        await self._reupload_one(ch, mid) for mid in message_ids
                    ]
                else:
                    res[ch.key] = await ch.message_api.forward_messages_from(
                        self._primary.private_file_channel, message_ids
                    )
            except Exception as ex:
                self._handle_write_error(ch.key, "content parts", ex)
        return res

    async def _reupload_one(self, ch: MirrorChannel, message_id: int) -> int:
        """Bandwidth-bound fallback: stream a part down and up again.

        Used when forwarding is impossible (``noforwards`` channels).
        """
        return await self._primary.reupload_to(
            message_id, ch.message_api.private_file_channel
        )

    # -- file descriptors --------------------------------------------------

    async def mirror_fd(
        self, text: str, existing: Optional[Dict[str, int]] = None
    ) -> Dict[str, int]:
        """Send or update the FD text message in every mirror channel.

        Returns the map of current FD message ids per channel: existing
        entries merged with this round's successful writes, so a channel
        that fails transiently keeps its (stale but recoverable) copy.
        """
        res: Dict[str, int] = dict(existing or {})
        for ch in self._channels:
            try:
                if mid := res.get(ch.key):
                    try:
                        res[ch.key] = await ch.message_api.edit_message_text(
                            message_id=mid, message=text
                        )
                        continue
                    except MessageNotFound:
                        logger.warning(
                            f"FD mirror message {mid} in channel {ch.key} is "
                            f"gone, sending a fresh copy"
                        )
                res[ch.key] = await ch.message_api.send_text(text)
            except Exception as ex:
                self._handle_write_error(ch.key, "file descriptor", ex)
        return res

    # -- pinned metadata ---------------------------------------------------

    async def mirror_pinned(
        self, primary_message_id: int, state: Dict[str, int]
    ) -> None:
        """Maintain a pinned copy of the metadata document in each mirror.

        The metadata blob is forwarded (preserving encryption), pinned,
        and the previous copy is deleted. ``state`` maps channel key to
        the current metadata message id in that channel and is updated
        in place.
        """
        for ch in self._channels:
            try:
                if self._mode == "reupload":
                    new_id = await self._reupload_one(ch, primary_message_id)
                else:
                    new_id = (
                        await ch.message_api.forward_messages_from(
                            self._primary.private_file_channel,
                            [primary_message_id],
                        )
                    )[0]
                await ch.message_api.pin_message(new_id)
                if (old := state.get(ch.key)) and old != new_id:
                    await ch.message_api.delete_messages(
                        [old], force=True
                    )
                state[ch.key] = new_id
            except Exception as ex:
                self._handle_write_error(ch.key, "pinned metadata", ex)

    async def adopt_pinned(
        self, new_ids: Dict[str, int], state: Dict[str, int]
    ) -> None:
        """Pin already-mirrored metadata copies (no forwarding needed).

        Used right after ``save`` has replicated the metadata blob as
        ordinary content: ``new_ids`` are the fresh copies per channel.
        """
        for channel_key, new_id in new_ids.items():
            if (ch := self._by_key.get(channel_key)) is None or new_id <= 0:
                continue
            try:
                await ch.message_api.pin_message(new_id)
                if (old := state.get(channel_key)) and old != new_id:
                    await ch.message_api.delete_messages([old], force=True)
                state[channel_key] = new_id
            except Exception as ex:
                self._handle_write_error(channel_key, "pinned metadata", ex)

    # -- deletion ----------------------------------------------------------

    async def delete(
        self, per_channel: Dict[str, List[int]], force: bool = False
    ) -> None:
        """Best-effort deletion of mirrored messages, per channel.

        Honors ``telegram.delete_messages_on_remove`` exactly like the
        primary-channel deletion does (the gate lives inside
        ``MessageApi.delete_messages``); ``force`` bypasses that gate for
        internal bookkeeping, matching ``MessageApi.delete_messages``.
        """
        for key, ids in per_channel.items():
            if not ids:
                continue
            if (api := self.api_for(key)) is None:
                logger.warning(
                    f"Cannot delete mirrored messages in channel {key}: "
                    f"channel is not configured as a mirror anymore"
                )
                continue
            await api.delete_messages(ids, force=force)

    # -- internals ---------------------------------------------------------

    def _handle_write_error(
        self, channel_key: str, what: str, ex: Exception
    ) -> None:
        if self._strict:
            if isinstance(ex, TechnicalError):
                raise ex
            raise TechnicalError(
                f"Mirroring {what} to channel {channel_key} failed: {ex}"
            ) from ex
        logger.error(
            f"Mirroring {what} to channel {channel_key} failed (non-strict, "
            f"continuing): {ex}"
        )
