import datetime
import json
from types import SimpleNamespace

import pytest

from tgfs.config import RedundancyConfig
from tgfs.core.backfill import backfill_mirrors
from tgfs.core.mirror import MirrorChannel, MirrorGroup
from tgfs.core.model import TGFSDirectory, TGFSFileDesc, TGFSFileRef, TGFSFileVersion
from tgfs.core.repository.impl.fd.tg_msg import TGMsgFDRepository
from tgfs.core.repository.impl.file_content import TGMsgFileContentRepository
from tgfs.core.repository.interface import FDRepositoryResp
from tgfs.errors import MessageNotFound, TechnicalError
from tgfs.reqres import Document, MessageResp, SentFileMessage


class TestRedundancyConfig:
    def test_from_dict_none(self):
        assert RedundancyConfig.from_dict(None) is None
        assert RedundancyConfig.from_dict({}) is None
        assert RedundancyConfig.from_dict({"mirrors": {}}) is None

    def test_from_dict_valid(self):
        config = RedundancyConfig.from_dict(
            {"mirrors": {"111": ["222", "333"]}, "mode": "forward", "strict": True}
        )
        assert config is not None
        assert config.mirrors == {"111": ["222", "333"]}
        assert config.mode == "forward"
        assert config.strict is True

    def test_from_dict_defaults(self):
        config = RedundancyConfig.from_dict({"mirrors": {"111": ["222"]}})
        assert config is not None
        assert config.mode == "forward"
        assert config.strict is False

    def test_from_dict_self_mirror_rejected(self):
        with pytest.raises(ValueError):
            RedundancyConfig.from_dict({"mirrors": {"111": ["111"]}})

    def test_from_dict_duplicate_mirror_rejected(self):
        with pytest.raises(ValueError):
            RedundancyConfig.from_dict({"mirrors": {"111": ["222", "222"]}})

    def test_from_dict_bad_mode_rejected(self):
        with pytest.raises(ValueError):
            RedundancyConfig.from_dict(
                {"mirrors": {"111": ["222"]}, "mode": "raid5"}
            )


class TestModelMirrors:
    def test_version_round_trip(self):
        fv = TGFSFileVersion(
            id="v1",
            updated_at=datetime.datetime.now(),
            message_ids=[1, 2],
            part_sizes=[10, 20],
            mirrors={"999": [11, 12]},
        )
        parsed = TGFSFileVersion.from_dict(fv.to_dict())  # type: ignore[arg-type]
        assert parsed.mirrors == {"999": [11, 12]}

    def test_version_without_mirrors_serializes_like_before(self):
        fv = TGFSFileVersion(
            id="v1",
            updated_at=datetime.datetime.now(),
            message_ids=[1],
        )
        assert "mirrors" not in fv.to_dict()
        parsed = TGFSFileVersion.from_dict(fv.to_dict())  # type: ignore[arg-type]
        assert parsed.mirrors == {}

    def test_version_from_sent_file_messages_aggregates_mirrors(self):
        fv = TGFSFileVersion.from_sent_file_message(
            SentFileMessage(message_id=1, size=10, mirrors={"999": 11}),
            SentFileMessage(message_id=2, size=20, mirrors={"999": 12}),
        )
        assert fv.mirrors == {"999": [11, 12]}

    def test_version_partial_mirror_padded_with_zero(self):
        fv = TGFSFileVersion.from_sent_file_message(
            SentFileMessage(message_id=1, size=10, mirrors={"999": 11}),
            SentFileMessage(message_id=2, size=20, mirrors={}),
        )
        assert fv.mirrors == {"999": [11, 0]}

    def test_file_ref_round_trip(self):
        root = TGFSDirectory.root_dir()
        fr = root.create_file_ref("a.txt", 5)
        fr.mirrors = {"999": 15}
        parsed = TGFSDirectory.from_dict(root.to_dict())
        assert parsed.find_file("a.txt").mirrors == {"999": 15}

    def test_file_ref_without_mirrors_serializes_like_before(self):
        root = TGFSDirectory.root_dir()
        root.create_file_ref("a.txt", 5)
        serialized = root.to_dict()
        assert "mirrors" not in serialized["files"][0]


def make_mirror_api(mocker, channel=999):
    api = mocker.AsyncMock()
    api.private_file_channel = channel
    return api


def make_group(mocker, strict=False, mode="forward", channel_key="999"):
    primary = mocker.AsyncMock()
    primary.private_file_channel = 111
    mirror_api = make_mirror_api(mocker)
    group = MirrorGroup(
        primary=primary,
        channels=[MirrorChannel(key=channel_key, message_api=mirror_api)],
        mode=mode,
        strict=strict,
    )
    return group, primary, mirror_api


class TestMirrorGroup:
    @pytest.mark.asyncio
    async def test_mirror_parts_forwards(self, mocker):
        group, _, mirror_api = make_group(mocker)
        mirror_api.forward_messages_from.return_value = [11, 12]

        res = await group.mirror_parts([1, 2])

        mirror_api.forward_messages_from.assert_awaited_once_with(111, [1, 2])
        assert res == {"999": [11, 12]}

    @pytest.mark.asyncio
    async def test_mirror_parts_non_strict_swallows_errors(self, mocker):
        group, _, mirror_api = make_group(mocker, strict=False)
        mirror_api.forward_messages_from.side_effect = Exception("boom")

        res = await group.mirror_parts([1, 2])

        assert res == {}

    @pytest.mark.asyncio
    async def test_mirror_parts_strict_raises(self, mocker):
        group, _, mirror_api = make_group(mocker, strict=True)
        mirror_api.forward_messages_from.side_effect = Exception("boom")

        with pytest.raises(TechnicalError):
            await group.mirror_parts([1, 2])

    def test_missing_channels(self, mocker):
        group, _, _ = make_group(mocker)
        assert group.missing_channels({}, 2) == ["999"]
        assert group.missing_channels({"999": [11]}, 2) == ["999"]
        assert group.missing_channels({"999": [11, 0]}, 2) == ["999"]
        assert group.missing_channels({"999": [11, 12]}, 2) == []

    @pytest.mark.asyncio
    async def test_mirror_fd_edits_existing(self, mocker):
        group, _, mirror_api = make_group(mocker)
        mirror_api.edit_message_text.return_value = 20

        res = await group.mirror_fd("{}", existing={"999": 20})

        mirror_api.edit_message_text.assert_awaited_once_with(
            message_id=20, message="{}"
        )
        mirror_api.send_text.assert_not_awaited()
        assert res == {"999": 20}

    @pytest.mark.asyncio
    async def test_mirror_fd_resends_when_edit_target_gone(self, mocker):
        group, _, mirror_api = make_group(mocker)
        mirror_api.edit_message_text.side_effect = MessageNotFound(message_id=20)
        mirror_api.send_text.return_value = 21

        res = await group.mirror_fd("{}", existing={"999": 20})

        assert res == {"999": 21}

    @pytest.mark.asyncio
    async def test_mirror_fd_keeps_stale_id_on_failure(self, mocker):
        group, _, mirror_api = make_group(mocker)
        mirror_api.edit_message_text.side_effect = Exception("boom")

        res = await group.mirror_fd("{}", existing={"999": 20})

        # A stale FD copy is still recoverable, so the id is kept.
        assert res == {"999": 20}


def make_sent_version(mirrors=None):
    return TGFSFileVersion(
        id="v1",
        updated_at=datetime.datetime.now(),
        message_ids=[1],
        part_sizes=[7],
        mirrors=mirrors or {},
    )


class TestContentFailover:
    @pytest.mark.asyncio
    async def test_get_serves_from_mirror_when_primary_fails(self, mocker):
        group, primary, mirror_api = make_group(mocker)
        repo = TGMsgFileContentRepository(primary, False, mirror_group=group)

        primary.download_file.side_effect = Exception("CHANNEL_PRIVATE")

        async def mirror_download(message_id, begin, end):
            assert message_id == 11

            async def chunks():
                yield b"mirror!"

            return mocker.Mock(chunks=chunks())

        mirror_api.download_file.side_effect = mirror_download

        fv = make_sent_version(mirrors={"999": [11]})
        result = await repo.get(fv, 0, -1, "a.txt")
        data = b"".join([chunk async for chunk in result])

        assert data == b"mirror!"
        assert group.primary_dead()

    @pytest.mark.asyncio
    async def test_get_raises_without_mirror(self, mocker):
        group, primary, _ = make_group(mocker)
        repo = TGMsgFileContentRepository(primary, False, mirror_group=group)
        primary.download_file.side_effect = Exception("boom")

        fv = make_sent_version()
        result = await repo.get(fv, 0, -1, "a.txt")
        with pytest.raises(Exception, match="boom"):
            async for _ in result:
                pass


def fd_json(message_ids, mirrors):
    fd = TGFSFileDesc(name="a.txt")
    fd.add_version(
        TGFSFileVersion(
            id="v1",
            updated_at=datetime.datetime.now(),
            message_ids=message_ids,
            mirrors=mirrors,
        )
    )
    return fd.to_json()


class TestFDFailover:
    @pytest.mark.asyncio
    async def test_fd_read_falls_back_to_mirror(self, mocker):
        group, primary, mirror_api = make_group(mocker)
        repo = TGMsgFDRepository(primary, mirror_group=group)

        root = TGFSDirectory.root_dir()
        fr = root.create_file_ref("a.txt", 5)
        fr.mirrors = {"999": 15}

        text = fd_json([100], {"999": [110]})
        doc = Document(
            size=7, id=1, access_hash=1, file_reference=b"", mime_type=None
        )

        async def primary_get(ids):
            # FD message and the content message are both gone.
            return [None for _ in ids]

        async def mirror_get(ids):
            res: list = []
            for mid in ids:
                if mid == 15:
                    res.append(MessageResp(message_id=15, text=text, document=None))
                elif mid == 110:
                    res.append(MessageResp(message_id=110, text="", document=doc))
                else:
                    res.append(None)
            return res

        primary.get_messages.side_effect = primary_get
        mirror_api.get_messages.side_effect = mirror_get

        fd = await repo.get(fr)

        version = fd.get_latest_version()
        assert version.is_valid()
        assert version.part_sizes == [7]

    @pytest.mark.asyncio
    async def test_save_mirrors_fd(self, mocker):
        group, primary, mirror_api = make_group(mocker)
        repo = TGMsgFDRepository(primary, mirror_group=group)
        primary.send_text.return_value = 5
        mirror_api.send_text.return_value = 15

        fd = TGFSFileDesc(name="a.txt")
        resp = await repo.save(fd)

        assert resp.message_id == 5
        assert resp.mirrors == {"999": 15}


class FakeFDRepo:
    def __init__(self, fd):
        self.fd = fd
        self.saved = []

    async def get(self, fr, include_all_versions=False):
        return self.fd

    async def save(self, fd, fr=None):
        self.saved.append((fd, fr))
        return FDRepositoryResp(
            message_id=fr.message_id if fr else 5,
            fd=fd,
            mirrors={"999": 15},
        )


class TestBackfill:
    @pytest.mark.asyncio
    async def test_backfill_mirrors_unmirrored_version(self, mocker):
        group, _, mirror_api = make_group(mocker)
        mirror_api.forward_messages_from.return_value = [11]

        root = TGFSDirectory.root_dir()
        fr = root.create_file_ref("a.txt", 5)

        fd = TGFSFileDesc(name="a.txt")
        fd.add_version(make_sent_version())
        fd_repo = FakeFDRepo(fd)

        metadata_api = mocker.AsyncMock()
        client = SimpleNamespace(
            name="test",
            mirror_group=group,
            fd_repo=fd_repo,
            metadata_api=metadata_api,
            dir_api=SimpleNamespace(root=root),
        )

        report = await backfill_mirrors(client)  # type: ignore[arg-type]

        assert report.files_scanned == 1
        assert report.versions_mirrored == 1
        assert report.failures == []
        assert fd.get_latest_version().mirrors == {"999": [11]}
        assert fr.mirrors == {"999": 15}
        assert len(fd_repo.saved) == 1
        metadata_api.push.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_backfill_skips_fully_mirrored(self, mocker):
        group, _, mirror_api = make_group(mocker)

        root = TGFSDirectory.root_dir()
        fr = root.create_file_ref("a.txt", 5)
        fr.mirrors = {"999": 15}

        fd = TGFSFileDesc(name="a.txt")
        fd.add_version(make_sent_version(mirrors={"999": [11]}))
        fd_repo = FakeFDRepo(fd)

        metadata_api = mocker.AsyncMock()
        client = SimpleNamespace(
            name="test",
            mirror_group=group,
            fd_repo=fd_repo,
            metadata_api=metadata_api,
            dir_api=SimpleNamespace(root=root),
        )

        report = await backfill_mirrors(client)  # type: ignore[arg-type]

        assert report.versions_mirrored == 0
        mirror_api.forward_messages_from.assert_not_awaited()
        assert fd_repo.saved == []
        metadata_api.push.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_backfill_without_mirror_group(self):
        client = SimpleNamespace(
            name="test",
            mirror_group=None,
            fd_repo=None,
            metadata_api=None,
            dir_api=SimpleNamespace(root=TGFSDirectory.root_dir()),
        )
        report = await backfill_mirrors(client)  # type: ignore[arg-type]
        assert report.failures


class TestSaveMirrorsParts:
    @pytest.mark.asyncio
    async def test_save_records_mirror_ids_on_sent_messages(self, mocker):
        group, primary, mirror_api = make_group(mocker)
        mirror_api.forward_messages_from.return_value = [11]

        repo = TGMsgFileContentRepository(primary, False, mirror_group=group)

        sent = mocker.patch.object(
            repo,
            "_send_file",
            mocker.AsyncMock(return_value=SentFileMessage(message_id=1, size=4)),
        )

        from tgfs.reqres import FileMessageFromBuffer

        res = await repo.save(FileMessageFromBuffer.new(buffer=b"data", name="a"))

        sent.assert_awaited_once()
        assert res[0].mirrors == {"999": 11}
