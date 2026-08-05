"""Backfill: mirror pre-existing data into the redundancy channels.

When redundancy is enabled on an existing installation, nothing that is
already in the channel has a mirror copy. This module walks the metadata
tree (the authoritative work list -- everything TGFS serves is reachable
from it), finds file versions without a complete mirror set, and copies
them using the same primitives as the live write path.

The job is idempotent and resumable for free: a version is skipped when
its ``mirrors`` map already covers every configured channel, and the FD
edit that records the map is the commit point of each unit of work. A
crash between forward and commit merely leaves an orphaned copy in the
mirror channel, which is harmless.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional, Tuple

from tgfs.core.model import TGFSDirectory, TGFSFileDesc, TGFSFileRef
from tgfs.tasks import task_store
from tgfs.tasks.models import TaskStatus, TaskType

if TYPE_CHECKING:
    from tgfs.core.client import Client

logger = logging.getLogger(__name__)


@dataclass
class BackfillReport:
    files_scanned: int = 0
    versions_checked: int = 0
    versions_mirrored: int = 0
    fds_mirrored: int = 0
    failures: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "versions_checked": self.versions_checked,
            "versions_mirrored": self.versions_mirrored,
            "fds_mirrored": self.fds_mirrored,
            "failures": self.failures,
        }


def _collect_file_refs(directory: TGFSDirectory) -> List[TGFSFileRef]:
    refs = list(directory.find_files())
    for child in directory.find_dirs():
        refs.extend(_collect_file_refs(child))
    return refs


async def _verify_mirrors(client: "Client", fd: TGFSFileDesc) -> None:
    """Drop mirror entries whose copies no longer exist.

    Mirror messages can be deleted manually just like primary ones; a
    dropped entry makes the version eligible for re-mirroring below.
    """
    if (mirror_group := client.mirror_group) is None:
        return
    for version in fd.get_versions(exclude_invalid=True):
        for channel_key in list(version.mirrors.keys()):
            if (api := mirror_group.api_for(channel_key)) is None:
                continue
            ids = [mid for mid in version.mirrors[channel_key] if mid > 0]
            if not ids:
                continue
            try:
                messages = await api.get_messages(ids)
            except Exception as ex:
                logger.warning(
                    f"Verification of mirror channel {channel_key} failed "
                    f"for {fd.name}@{version.id}: {ex}"
                )
                continue
            if any(m is None or m.document is None for m in messages):
                logger.warning(
                    f"Mirror copy of {fd.name}@{version.id} in channel "
                    f"{channel_key} is incomplete, scheduling re-mirror"
                )
                del version.mirrors[channel_key]


async def _backfill_file(
    client: "Client", fr: TGFSFileRef, verify: bool, report: BackfillReport
) -> None:
    mirror_group = client.mirror_group
    fd_repo = client.fd_repo
    if mirror_group is None or fd_repo is None:
        return

    fd = await fd_repo.get(fr, include_all_versions=True)  # type: ignore[call-arg]
    if not fd.get_versions():
        # Unreadable or fully invalid descriptor (fd_repo.get returns an
        # empty FD in that case). Never save it back -- that would
        # overwrite the real descriptor message with an empty one.
        return
    if verify:
        await _verify_mirrors(client, fd)

    changed = False
    for version in fd.get_versions(exclude_invalid=True):
        report.versions_checked += 1
        missing = mirror_group.missing_channels(
            version.mirrors, len(version.message_ids)
        )
        if not missing:
            continue
        mirrored = await mirror_group.mirror_parts(
            version.message_ids, only_channels=missing
        )
        if mirrored:
            version.mirrors.update(mirrored)
            report.versions_mirrored += 1
            changed = True
        still_missing = [key for key in missing if key not in mirrored]
        if still_missing:
            report.failures.append(
                f"{fr.name}@{version.id}: could not mirror to "
                f"{', '.join(still_missing)}"
            )

    fd_missing = set(mirror_group.channel_keys) - {
        key for key, mid in fr.mirrors.items() if mid > 0
    }

    if changed or fd_missing:
        # Commit point: the (possibly updated) mirrors map is persisted
        # in the FD message, and the FD itself gets its mirror copies.
        resp = await fd_repo.save(fd, fr)
        if resp.mirrors != fr.mirrors or resp.message_id != fr.message_id:
            fr.message_id = resp.message_id
            fr.mirrors = dict(resp.mirrors)
        if fd_missing:
            report.fds_mirrored += 1


async def backfill_mirrors(
    client: "Client",
    verify: bool = False,
    task_id: Optional[str] = None,
) -> BackfillReport:
    """Mirror every unmirrored file version of ``client``'s channel.

    Files are processed newest first so the most recent data is
    protected earliest. Failures are recorded and skipped -- rerunning
    the job retries exactly the missing pieces.
    """
    report = BackfillReport()

    if client.mirror_group is None or client.fd_repo is None:
        report.failures.append(
            f"Channel '{client.name}' has no mirror channels configured"
        )
        return report

    refs = _collect_file_refs(client.dir_api.root)

    # Newest first: load descriptors to know each file's timestamp.
    dated: List[Tuple[TGFSFileRef, int]] = []
    for fr in refs:
        try:
            fd = await client.fd_repo.get(fr)
            dated.append((fr, fd.updated_at_timestamp))
        except Exception as ex:
            report.failures.append(f"{fr.name}: cannot read descriptor ({ex})")
    dated.sort(key=lambda pair: pair[1], reverse=True)

    if task_id:
        await task_store.update_task_progress(
            task_id, status=TaskStatus.IN_PROGRESS
        )

    metadata_dirty = False
    for fr, _ in dated:
        before = (fr.message_id, dict(fr.mirrors))
        try:
            await _backfill_file(client, fr, verify, report)
        except Exception as ex:
            report.failures.append(f"{fr.name}: {ex}")
            logger.error(f"Backfill failed for {fr.name}: {ex}")
        if before != (fr.message_id, fr.mirrors):
            metadata_dirty = True
        report.files_scanned += 1
        if task_id:
            await task_store.update_task_progress(task_id, size_delta=1)

    if metadata_dirty and client.metadata_api:
        await client.metadata_api.push()

    if task_id:
        await task_store.update_task_progress(
            task_id,
            status=(
                TaskStatus.COMPLETED if not report.failures else TaskStatus.FAILED
            ),
            error_message="; ".join(report.failures) or None,
        )

    logger.info(
        f"Backfill for '{client.name}' finished: "
        f"{report.versions_mirrored}/{report.versions_checked} versions "
        f"mirrored, {len(report.failures)} failures"
    )
    return report


async def create_backfill_task(client: "Client", total_files: int) -> str:
    return await task_store.add_task(
        task_type=TaskType.MIRROR_BACKFILL,
        path=f"/{client.name}",
        filename=f"mirror-backfill-{client.name}",
        size_total=total_files,
    )


def count_files(client: "Client") -> int:
    return len(_collect_file_refs(client.dir_api.root))
