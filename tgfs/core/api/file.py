import logging
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
from uuid import uuid4 as uuid

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

    async def delete_mirrored(
        self, mirror_ids: MirrorMessageIds, force: bool = False
    ) -> None:
        if self._mirror_group and mirror_ids:
            await self._mirror_group.delete(mirror_ids, force=force)

    @classmethod
    def _iter_file_refs(cls, directory: TGFSDirectory) -> Iterator[TGFSFileRef]:
        yield from directory.find_files()
        for child in directory.find_dirs():
            yield from cls._iter_file_refs(child)

    def _descriptors_referenced_elsewhere(
        self, removing: Iterable[TGFSFileRef]
    ) -> Set[int]:
        """Descriptor message ids that survive removing ``removing``.

        Copies used to be made by pointing a second file ref at the *same*
        descriptor message, so both files were backed by one set of Telegram
        messages. Removing either of them would then leave the other one
        pointing at messages that no longer exist -- reported by WebDAV as a
        0-byte file. New copies own their content, but metadata written
        before that still holds such pairs, so removals keep checking.
        """
        removing_ids = {id(fr) for fr in removing}
        return {
            fr.message_id
            for fr in self._iter_file_refs(self._metadata_api.get_root_directory())
            if id(fr) not in removing_ids and fr.message_id > 0
        }

    async def collect_deletable_message_ids(
        self, frs: Sequence[TGFSFileRef]
    ) -> Tuple[List[int], MirrorMessageIds]:
        """Message ids that become garbage once ``frs`` are removed.

        Refs whose descriptor is still referenced by a file outside ``frs``
        contribute nothing: their messages are shared and must stay.
        """
        shared = self._descriptors_referenced_elsewhere(frs)
        ids: List[int] = []
        mirror_ids: MirrorMessageIds = {}
        for fr in frs:
            if fr.message_id in shared:
                logger.info(
                    f"Keeping the telegram messages of {fr.name} "
                    f"(descriptor {fr.message_id}): another file still refers to them"
                )
                continue
            fr_ids, fr_mirror_ids = await self.collect_all_message_ids(fr)
            ids.extend(fr_ids)
            for channel_key, channel_ids in fr_mirror_ids.items():
                mirror_ids.setdefault(channel_key, []).extend(channel_ids)
        return ids, mirror_ids

    async def _duplicate_versions(self, fd: TGFSFileDesc) -> TGFSFileDesc:
        """Build a descriptor whose versions own fresh content messages.

        Every part of every version is duplicated inside the channel in one
        server-side call, so the copy costs the same whether the file is a
        kilobyte or a hundred gigabytes. Timestamps and part sizes carry
        over, so the copy keeps the full history; the versions get fresh ids
        because two files that are meant to be independent should not share
        an identifier with each other.
        """
        versions = fd.get_versions(sort=True)
        parts = [mid for version in versions for mid in version.message_ids]
        new_parts = await self._message_api.duplicate_messages(parts)

        mirrors: Dict[str, List[int]] = {}
        if self._mirror_group and new_parts:
            mirrors = await self._mirror_group.mirror_parts(new_parts)

        copied = TGFSFileDesc(name=fd.name)
        version_ids: Dict[str, str] = {}
        offset = 0
        for version in versions:
            n = len(version.message_ids)
            version_ids[version.id] = str(uuid())
            copied.add_version(
                TGFSFileVersion(
                    id=version_ids[version.id],
                    updated_at=version.updated_at,
                    message_ids=new_parts[offset : offset + n],
                    part_sizes=list(version.part_sizes),
                    mirrors={
                        channel_key: ids[offset : offset + n]
                        for channel_key, ids in mirrors.items()
                    },
                )
            )
            offset += n
        # add_version derives created_at from the versions it is given; the
        # copy should carry the original's creation date instead.
        copied.created_at = fd.created_at
        if latest := version_ids.get(fd.latest_version_id):
            copied.latest_version_id = latest
        return copied

    async def copy(
        self, where: TGFSDirectory, fr: TGFSFileRef, name: Optional[str] = None
    ) -> TGFSFileRef:
        """Copy a file without moving a single byte of its content.

        The copy gets its own descriptor and its own content messages, so
        writing to it -- or deleting it -- leaves the original alone.
        """
        fd = await self._file_desc_api.get_file_desc(fr, include_all_versions=True)
        copied_fd = await self._duplicate_versions(fd)
        resp: Optional[FDRepositoryResp] = None
        try:
            resp = await self._file_desc_api.save_new_file_desc(copied_fd)
            copied_fr = where.create_file_ref(name or fr.name, resp.message_id)
        except Exception:
            await self._discard_orphans(copied_fd, resp)
            raise
        copied_fr.mirrors = dict(resp.mirrors)
        await self._metadata_api.push()
        return copied_fr

    async def _discard_orphans(
        self, fd: TGFSFileDesc, resp: Optional[FDRepositoryResp] = None
    ) -> None:
        """Drop the messages of a copy that never made it into the metadata.

        Nothing refers to them, and they were created moments ago by this
        very call, so they are cleaned up regardless of the user's setting
        for keeping removed file messages.
        """
        message_ids: List[int] = []
        mirror_ids: MirrorMessageIds = {}
        if resp is not None:
            message_ids.append(resp.message_id)
            _merge_mirror_ids(mirror_ids, resp.mirrors)
        for version in fd.get_versions():
            message_ids.extend(mid for mid in version.message_ids if mid > 0)
            for channel_key, ids in version.mirrors.items():
                mirror_ids.setdefault(channel_key, []).extend(
                    mid for mid in ids if mid > 0
                )
        try:
            await self._message_api.delete_messages(message_ids, force=True)
            await self.delete_mirrored(mirror_ids, force=True)
        except Exception as ex:
            logger.warning(f"Could not clean up after a failed copy: {ex}")

    async def move(
        self, fr: TGFSFileRef, where: TGFSDirectory, name: Optional[str] = None
    ) -> TGFSFileRef:
        """Relocate ``fr`` without re-uploading or deleting anything.

        Implementing a move as copy-then-remove would delete the very
        messages the copy points at, so the moved file has to be relocated in
        the metadata instead.
        """
        moved_fr = fr.location.relocate_file_ref(fr, where, name)
        await self._metadata_api.push()
        return moved_fr

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
            message_ids, mirror_ids = await self.collect_deletable_message_ids([fr])
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

    async def desc(
        self, fr: TGFSFileRef, include_all_versions: bool = False
    ) -> TGFSFileDesc:
        return await self._file_desc_api.get_file_desc(fr, include_all_versions)

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
