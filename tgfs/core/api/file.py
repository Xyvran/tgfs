import logging
from typing import Dict, List, Optional, Tuple

from tgfs.core.mirror import MirrorGroup
from tgfs.core.model import TGFSDirectory, TGFSFileDesc, TGFSFileRef, TGFSFileVersion
from tgfs.core.repository.interface import FDRepositoryResp
from tgfs.errors import FileOrDirectoryDoesNotExist
from tgfs.reqres import (
    FileContent,
    FileMessage,
    FileMessageEmpty,
)

from .file_desc import FileDescApi
from .message import MessageApi
from .metadata import MetaDataApi

logger = logging.getLogger(__name__)

# {mirror channel id -> message ids to delete there}
MirrorMessageIds = Dict[str, List[int]]


def _merge_mirror_ids(target: MirrorMessageIds, source: Dict[str, int]) -> None:
    for channel_key, mid in source.items():
        if mid > 0:
            target.setdefault(channel_key, []).append(mid)


class FileApi:
    def __init__(
        self,
        metadata_api: MetaDataApi,
        file_desc_api: FileDescApi,
        message_api: MessageApi,
        mirror_group: Optional[MirrorGroup] = None,
    ):
        self._metadata_api = metadata_api
        self._file_desc_api = file_desc_api
        self._message_api = message_api
        self._mirror_group = mirror_group

    async def collect_message_ids(self, fr: TGFSFileRef) -> List[int]:
        """Return every primary-channel message id backing ``fr``.

        Includes the file descriptor message itself plus every content
        message across all known versions. Returns just the descriptor
        id if the descriptor can no longer be read (it may already be
        gone), so callers can still try to delete that one message.
        """
        primary, _ = await self.collect_all_message_ids(fr)
        return primary

    async def collect_all_message_ids(
        self, fr: TGFSFileRef
    ) -> Tuple[List[int], MirrorMessageIds]:
        """Like :meth:`collect_message_ids`, but also returns the message
        ids of every mirrored copy, grouped by mirror channel."""
        ids: List[int] = []
        mirror_ids: MirrorMessageIds = {}
        if fr.message_id > 0:
            ids.append(fr.message_id)
        _merge_mirror_ids(mirror_ids, fr.mirrors)
        try:
            fd = await self._file_desc_api.get_file_desc(fr)
        except Exception as ex:
            logger.warning(
                f"Could not load file descriptor for {fr.name} "
                f"(message_id={fr.message_id}): {ex}"
            )
            return ids, mirror_ids
        for version in fd.get_versions():
            ids.extend(mid for mid in version.message_ids if mid > 0)
            for channel_key, version_mirror_ids in version.mirrors.items():
                mirror_ids.setdefault(channel_key, []).extend(
                    mid for mid in version_mirror_ids if mid > 0
                )
        return ids, mirror_ids

    async def _collect_version_message_ids(
        self, fr: TGFSFileRef, version_id: str
    ) -> Tuple[List[int], MirrorMessageIds]:
        try:
            fd = await self._file_desc_api.get_file_desc(fr)
            version = fd.get_version(version_id)
        except Exception as ex:
            logger.warning(
                f"Could not load version {version_id} of {fr.name}: {ex}"
            )
            return [], {}
        mirror_ids: MirrorMessageIds = {
            channel_key: [mid for mid in ids if mid > 0]
            for channel_key, ids in version.mirrors.items()
        }
        return [mid for mid in version.message_ids if mid > 0], mirror_ids

    async def delete_mirrored(self, mirror_ids: MirrorMessageIds) -> None:
        if self._mirror_group and mirror_ids:
            await self._mirror_group.delete(mirror_ids)

    async def copy(
        self, where: TGFSDirectory, fr: TGFSFileRef, name: Optional[str] = None
    ) -> TGFSFileRef:
        copied_fr = where.create_file_ref(name or fr.name, fr.message_id)
        copied_fr.mirrors = dict(fr.mirrors)
        await self._metadata_api.push()
        return copied_fr

    async def _create_new_file(
        self, where: TGFSDirectory, file_msg: FileMessage
    ) -> TGFSFileDesc:
        resp = await self._file_desc_api.create_file_desc(file_msg)
        fr = where.create_file_ref(file_msg.name, resp.message_id)
        fr.mirrors = dict(resp.mirrors)
        await self._metadata_api.push()
        return resp.fd

    async def _sync_file_ref(self, fr: TGFSFileRef, resp: FDRepositoryResp) -> None:
        """
        Sync the file ref with the descriptor's current location: the primary
        message_id may change if the original message went missing (e.g. it was
        manually deleted), and the mirror map changes whenever mirror copies
        are (re)written.
        """
        if fr.message_id != resp.message_id or fr.mirrors != resp.mirrors:
            fr.message_id = resp.message_id
            fr.mirrors = dict(resp.mirrors)
            await self._metadata_api.push()

    async def _update_existing_file(
        self, fr: TGFSFileRef, file_msg: FileMessage, version_id: Optional[str]
    ) -> TGFSFileDesc:
        if version_id:
            resp = await self._file_desc_api.update_file_version(
                fr, file_msg, version_id
            )
        else:
            resp = await self._file_desc_api.append_file_version(file_msg, fr)
        await self._sync_file_ref(fr, resp)
        return resp.fd

    async def rm(self, fr: TGFSFileRef, version_id: Optional[str] = None) -> None:
        if not version_id:
            message_ids, mirror_ids = await self.collect_all_message_ids(fr)
            fr.delete()
            await self._metadata_api.push()
            await self._message_api.delete_messages(message_ids)
            await self.delete_mirrored(mirror_ids)
        else:
            message_ids, mirror_ids = await self._collect_version_message_ids(
                fr, version_id
            )
            resp = await self._file_desc_api.delete_file_version(fr, version_id)
            await self._sync_file_ref(fr, resp)
            await self._message_api.delete_messages(message_ids)
            await self.delete_mirrored(mirror_ids)

    async def upload(
        self,
        under: TGFSDirectory,
        file_msg: FileMessage,
        version_id: Optional[str] = None,
    ) -> TGFSFileDesc:
        try:
            fr = under.find_file(file_msg.name)
            return await self._update_existing_file(fr, file_msg, version_id)
        except FileOrDirectoryDoesNotExist:
            return await self._create_new_file(under, file_msg)

    async def desc(self, fr: TGFSFileRef) -> TGFSFileDesc:
        return await self._file_desc_api.get_file_desc(fr)

    async def retrieve(
        self,
        fr: TGFSFileRef,
        begin: int,
        end: int,
        as_name: str,
    ) -> FileContent:
        fd = await self.desc(fr)
        if isinstance(fd, FileMessageEmpty):

            async def empty_file() -> FileContent:
                yield b""

            return empty_file()
        fv = fd.get_latest_version()

        async def chunks():
            try:
                async for chunk in await self._file_desc_api.download_file_at_version(
                    fv, begin, end, as_name or fr.name
                ):
                    yield chunk

            except Exception as ex:
                raise ex

        return chunks()

    async def retrieve_version(
        self,
        fv: TGFSFileVersion,
        begin: int,
        end: int,
        as_name: str,
    ) -> FileContent:
        return await self._file_desc_api.download_file_at_version(
            fv,
            begin,
            end,
            as_name,
        )
