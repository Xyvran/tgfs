import json
import logging
from itertools import chain
from typing import Dict, List, Optional, Tuple

from tgfs.core.api import MessageApi
from tgfs.core.mirror import MirrorGroup
from tgfs.core.model import TGFSFileDesc, TGFSFileRef
from tgfs.core.repository.interface import (
    FDRepositoryResp,
    IFDRepository,
)
from tgfs.errors import MessageNotFound

logger = logging.getLogger(__name__)


class TGMsgFDRepository(IFDRepository):
    def __init__(
        self,
        message_api: MessageApi,
        mirror_group: Optional[MirrorGroup] = None,
    ):
        self._message_api = message_api
        self._mirror_group = mirror_group

    async def save(
        self, fd: TGFSFileDesc, fr: Optional[TGFSFileRef] = None
    ) -> FDRepositoryResp:
        # If file_content referer is None, create a new file_content descriptor message.
        if fr is None:
            return FDRepositoryResp(
                message_id=await self._message_api.send_text(fd.to_json()),
                fd=fd,
                mirrors=await self._mirror_fd(fd, existing=None),
            )

        # If file_content referer is provided, try to update the existing file_content descriptor.
        # But if the message is not found (probably got deleted manually), a new file_content descriptor will be created.
        try:
            return FDRepositoryResp(
                message_id=await self._message_api.edit_message_text(
                    message_id=fr.message_id, message=fd.to_json()
                ),
                fd=fd,
                mirrors=await self._mirror_fd(fd, existing=fr.mirrors),
            )
        except MessageNotFound:
            return await self.save(fd)

    async def _mirror_fd(
        self, fd: TGFSFileDesc, existing: Optional[Dict[str, int]]
    ) -> Dict[str, int]:
        """Keep a copy of the FD text message in every mirror channel.

        Descriptors are sent as fresh text messages (not forwarded)
        because they are edited on every new version and a forwarded
        message cannot be edited in the target channel.
        """
        if not self._mirror_group:
            return dict(existing or {})
        return await self._mirror_group.mirror_fd(fd.to_json(), existing)

    async def _lookup_mirror_parts(
        self, missing: List[Tuple[str, int]]
    ) -> Dict[Tuple[str, int], int]:
        """Fetch mirror copies of content messages, batched per channel.

        ``missing`` is a list of (channel_key, message_id) pairs; the
        result maps each found pair to the document size of the copy.
        """
        res: Dict[Tuple[str, int], int] = {}
        if not self._mirror_group:
            return res
        by_channel: Dict[str, List[int]] = {}
        for channel_key, mid in missing:
            by_channel.setdefault(channel_key, []).append(mid)
        for channel_key, mids in by_channel.items():
            if (api := self._mirror_group.api_for(channel_key)) is None:
                continue
            try:
                messages = await api.get_messages(mids)
            except Exception as ex:
                logger.warning(
                    f"Could not check mirror channel {channel_key} for "
                    f"messages {mids}: {ex}"
                )
                continue
            for mid, message in zip(mids, messages):
                if message and message.document:
                    res[(channel_key, mid)] = message.document.size
        return res

    async def _validate_fv(
        self, fd: TGFSFileDesc, include_all_versions: bool
    ) -> TGFSFileDesc:
        versions = fd.get_versions(exclude_invalid=True)

        # Files in the channel may be deleted manually, so we need to check if the messages for the versions exist.

        file_messages = await self._message_api.get_messages(
            list(chain(*(version.message_ids for version in versions)))
        )

        message_map = {msg.message_id: msg for msg in file_messages if msg}

        has_valid_version = False

        for i, version in enumerate(versions):
            for j, message_id in enumerate(version.message_ids):
                if (
                    file_message := message_map.get(message_id, None)
                ) and file_message.document:
                    version.part_sizes.append(file_message.document.size)
                    continue

                # The primary copy of this part is gone -- before declaring
                # the version invalid, check whether a mirror still has it.
                mirror_candidates = [
                    (channel_key, mirror_ids[j])
                    for channel_key, mirror_ids in version.mirrors.items()
                    if j < len(mirror_ids) and mirror_ids[j] > 0
                ]
                mirror_sizes = await self._lookup_mirror_parts(mirror_candidates)
                if mirror_sizes:
                    logger.warning(
                        f"File message {message_id} for part {j + 1} of "
                        f"{fd.name}@{version.id} not found in the primary "
                        f"channel, serving from mirror"
                    )
                    version.part_sizes.append(next(iter(mirror_sizes.values())))
                    continue

                logger.warning(
                    f"File message {message_id} for part {j + 1} of {fd.name}@{version.id} not found"
                )
                version.set_invalid()
                break
            if version.is_valid():
                has_valid_version = True
                if not include_all_versions:
                    # Found a valid version, no need to check further
                    return fd

        return fd if has_valid_version else TGFSFileDesc.empty(fd.name)

    async def _get_fd_text(self, fr: TGFSFileRef) -> Optional[str]:
        """Read the FD JSON, falling back to mirror copies if needed."""
        try:
            message = (await self._message_api.get_messages([fr.message_id]))[0]
        except Exception as ex:
            logger.warning(
                f"Could not read file descriptor {fr.message_id} for "
                f"{fr.name} from the primary channel: {ex}"
            )
            message = None
            if self._mirror_group:
                self._mirror_group.mark_primary_dead()

        if message and message.text:
            return message.text

        if not self._mirror_group:
            return None

        for channel_key, mirror_mid in fr.mirrors.items():
            if (api := self._mirror_group.api_for(channel_key)) is None:
                continue
            try:
                mirror_message = (await api.get_messages([mirror_mid]))[0]
            except Exception as ex:
                logger.warning(
                    f"Could not read FD mirror {mirror_mid} in channel "
                    f"{channel_key} for {fr.name}: {ex}"
                )
                continue
            if mirror_message and mirror_message.text:
                logger.warning(
                    f"Serving file descriptor for {fr.name} from mirror "
                    f"channel {channel_key}"
                )
                return mirror_message.text
        return None

    async def get(
        self, fr: TGFSFileRef, include_all_versions: bool = False
    ) -> TGFSFileDesc:
        text = await self._get_fd_text(fr)

        if not text:
            logging.error(
                f"File descriptor (message_id: {fr.message_id}) for {fr.name} not found"
            )
            return TGFSFileDesc.empty(fr.name)

        fd = TGFSFileDesc.from_dict(json.loads(text), name=fr.name)
        return await self._validate_fv(fd, include_all_versions)
