import os
import stat

import asyncssh
import pytest
from tgfs.app.sftp import start_sftp_server
from tgfs.app.sftp.host_key import load_or_create_host_key
from tgfs.config import SFTPConfig


def build_config(mocker, sftp_cfg):
    config = mocker.Mock()
    config.tgfs.users = {}
    config.tgfs.sftp = sftp_cfg
    return config


def ephemeral_config(tmp_path) -> SFTPConfig:
    return SFTPConfig(
        enabled=True,
        host="127.0.0.1",
        port=0,
        host_key_file=str(tmp_path / "host_key"),
        authorized_keys_dir=None,
        upload_buffer_size_mb=1,
        upload_buffer_dir=None,
    )


class TestHostKey:
    def test_is_generated_on_first_use(self, tmp_path):
        path = str(tmp_path / "keys" / "host_key")

        key = load_or_create_host_key(path)

        assert os.path.exists(path)
        assert key.get_fingerprint()

    def test_is_only_readable_by_the_owner(self, tmp_path):
        path = str(tmp_path / "host_key")
        load_or_create_host_key(path)

        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_is_reused_on_the_next_start(self, tmp_path):
        path = str(tmp_path / "host_key")

        first = load_or_create_host_key(path)
        second = load_or_create_host_key(path)

        assert first.get_fingerprint() == second.get_fingerprint()


class TestStartSftpServer:
    async def test_returns_nothing_when_disabled(self, mocker):
        config = build_config(mocker, SFTPConfig.from_dict({"enabled": False}))

        assert await start_sftp_server({}, config) is None

    async def test_listens_and_generates_a_host_key(self, mocker, tmp_path):
        config = build_config(
            mocker,
            # Port 0 asks the OS for a free one; the config parser rightly
            # refuses it, so build the object directly here.
            ephemeral_config(tmp_path),
        )

        acceptor = await start_sftp_server({}, config)
        assert acceptor is not None
        try:
            assert acceptor.get_port() > 0
            assert (tmp_path / "host_key").exists()
        finally:
            acceptor.close()
            await acceptor.wait_closed()

    async def test_a_taken_port_is_reported(self, mocker, tmp_path):
        config = build_config(
            mocker,
            # Port 0 asks the OS for a free one; the config parser rightly
            # refuses it, so build the object directly here.
            ephemeral_config(tmp_path),
        )
        first = await start_sftp_server({}, config)
        assert first is not None

        try:
            config.tgfs.sftp.port = first.get_port()
            with pytest.raises(OSError):
                await start_sftp_server({}, config)
        finally:
            first.close()
            await first.wait_closed()


class TestHostKeyPathResolution:
    def test_relative_paths_resolve_against_the_data_directory(self):
        config = SFTPConfig.from_dict({"host_key_file": "keys/host_key"})

        assert config.host_key_file.endswith(os.path.join("keys", "host_key"))
        assert os.path.isabs(config.host_key_file) or config.host_key_file.startswith(
            "."
        )


class TestAsyncsshAvailability:
    def test_the_ed25519_algorithm_is_supported(self):
        key = asyncssh.generate_private_key("ssh-ed25519")

        assert key.get_algorithm() == "ssh-ed25519"
