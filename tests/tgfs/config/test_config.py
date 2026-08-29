import pytest
from tgfs.config import (
    WebDAVConfig,
    ManagerConfig,
    UserConfig,
    JWTConfig,
    ServerConfig,
    SFTPConfig,
    TGFSConfig,
    TransferConfig,
    Config,
    GithubRepoConfig,
    MetadataConfig,
    MetadataType,
    MetadataConfigDict,
)


class TestWebDAVConfig:
    def test_from_dict(self):
        data = {"host": "localhost", "port": 8080, "path": "/webdav"}
        config = WebDAVConfig.from_dict(data)

        assert config.host == "localhost"
        assert config.port == 8080
        assert config.path == "/webdav"


class TestManagerConfig:
    def test_from_dict(self):
        data = {"host": "0.0.0.0", "port": 9000}
        config = ManagerConfig.from_dict(data)

        assert config.host == "0.0.0.0"
        assert config.port == 9000


class TestUserConfig:
    def test_from_dict_readonly_false(self):
        data = {"password": "secret", "readonly": False}
        config = UserConfig.from_dict(data)

        assert config.password == "secret"
        assert config.readonly is False

    def test_from_dict_readonly_default_false(self):
        data = {"password": "secret"}
        config = UserConfig.from_dict(data)

        assert config.password == "secret"
        assert config.readonly is False

    def test_from_dict_readonly_true(self):
        data = {"password": "secret", "readonly": True}
        config = UserConfig.from_dict(data)

        assert config.password == "secret"
        assert config.readonly is True


class TestJWTConfig:
    def test_from_dict(self):
        data = {"secret": "jwt_secret", "algorithm": "HS256", "life": 3600}
        config = JWTConfig.from_dict(data)

        assert config.secret == "jwt_secret"
        assert config.algorithm == "HS256"
        assert config.life == 3600


class TestServerConfig:
    def test_from_dict(self):
        data = {"host": "127.0.0.1", "port": 8000}
        config = ServerConfig.from_dict(data)

        assert config.host == "127.0.0.1"
        assert config.port == 8000


class TestTGFSConfig:
    def test_from_dict_minimal(self):
        data = {
            "users": {},
            "jwt": {"secret": "test", "algorithm": "HS256", "life": 1800},
            "server": {"host": "localhost", "port": 3000},
        }
        config = TGFSConfig.from_dict(data)

        assert config.users == {}
        assert config.jwt.secret == "test"
        assert config.server.host == "localhost"

    def test_from_dict_with_users(self):
        data = {
            "users": {
                "admin": {"password": "admin123", "readonly": False},
                "viewer": {"password": "view123", "readonly": True},
            },
            "jwt": {"secret": "test", "algorithm": "HS256", "life": 1800},
            "server": {"host": "localhost", "port": 3000},
        }
        config = TGFSConfig.from_dict(data)

        assert "admin" in config.users
        assert "viewer" in config.users
        assert config.users["admin"].password == "admin123"
        assert config.users["admin"].readonly is False
        assert config.users["viewer"].readonly is True

    def test_from_dict_no_users(self):
        data = {
            "users": None,
            "jwt": {"secret": "test", "algorithm": "HS256", "life": 1800},
            "server": {"host": "localhost", "port": 3000},
        }
        config = TGFSConfig.from_dict(data)

        assert config.users == {}

    def test_from_dict_without_sftp_block(self):
        data = {
            "users": {},
            "jwt": {"secret": "test", "algorithm": "HS256", "life": 1800},
            "server": {"host": "localhost", "port": 3000},
        }
        config = TGFSConfig.from_dict(data)

        assert config.sftp.enabled is False
        assert config.sftp.port == SFTPConfig.DEFAULT_PORT

    def test_from_dict_with_sftp_block(self):
        data = {
            "users": {},
            "jwt": {"secret": "test", "algorithm": "HS256", "life": 1800},
            "server": {"host": "localhost", "port": 3000},
            "sftp": {"enabled": True, "port": 2200},
        }
        config = TGFSConfig.from_dict(data)

        assert config.sftp.enabled is True
        assert config.sftp.port == 2200


class TestSFTPConfig:
    def test_defaults(self):
        config = SFTPConfig.from_dict(None)

        assert config.enabled is False
        assert config.host == "0.0.0.0"
        assert config.port == SFTPConfig.DEFAULT_PORT
        assert config.host_key_file.endswith(SFTPConfig.DEFAULT_HOST_KEY_FILE)
        assert config.authorized_keys_dir is None
        assert config.upload_buffer_dir is None
        assert (
            config.upload_buffer_size_mb == SFTPConfig.DEFAULT_UPLOAD_BUFFER_SIZE_MB
        )

    def test_full_block(self):
        config = SFTPConfig.from_dict(
            {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 2200,
                "host_key_file": "keys/host_key",
                "authorized_keys_dir": "keys/authorized",
                "upload_buffer_size_mb": 8,
                "upload_buffer_dir": "spool",
            }
        )

        assert config.enabled is True
        assert config.host == "127.0.0.1"
        assert config.port == 2200
        assert config.host_key_file.endswith("host_key")
        assert config.authorized_keys_dir is not None
        assert config.authorized_keys_dir.endswith("authorized")
        assert config.upload_buffer_size_mb == 8
        assert config.upload_buffer_size_bytes == 8 * 1024 * 1024
        assert config.upload_buffer_dir is not None

    @pytest.mark.parametrize("port", [0, 65536, -1])
    def test_rejects_invalid_port(self, port):
        with pytest.raises(ValueError):
            SFTPConfig.from_dict({"port": port})

    def test_rejects_negative_buffer_size(self):
        with pytest.raises(ValueError):
            SFTPConfig.from_dict({"upload_buffer_size_mb": -1})


class TestTransferConfig:
    def test_defaults_when_absent(self):
        """An existing config.yaml has no transfer block and must still load."""
        config = TGFSConfig.from_dict(
            {
                "users": {},
                "jwt": {"secret": "test", "algorithm": "HS256", "life": 1800},
                "server": {"host": "localhost", "port": 3000},
            }
        )

        assert config.transfer.upload_workers_small == 3
        assert config.transfer.upload_workers_big == 8
        assert config.transfer.upload_part_size_kb == 512
        assert config.transfer.download_pieces_in_flight == 4
        assert config.transfer.connection_pool_size == 1
        assert config.transfer.chunk_cache_mb == 0

    def test_overrides(self):
        config = TransferConfig.from_dict(
            {
                "upload_workers_big": 12,
                "upload_part_size_kb": 256,
                "download_piece_size_kb": 8192,
                "download_pieces_in_flight": 6,
                "parallel_download_threshold_mb": 32,
                "connection_pool_size": 4,
                "chunk_cache_mb": 128,
                "chunk_cache_readahead": 3,
            }
        )

        assert config.upload_workers_big == 12
        assert config.upload_part_size_bytes == 256 * 1024
        assert config.download_piece_size_bytes == 8192 * 1024
        assert config.parallel_download_threshold_bytes == 32 * 1024 * 1024
        assert config.chunk_cache_bytes == 128 * 1024 * 1024

    @pytest.mark.parametrize(
        "part_size", [700, 300, 1024]
    )
    def test_rejects_part_sizes_telegram_would_refuse(self, part_size):
        """Telegram only accepts part sizes that divide 512 KiB."""
        with pytest.raises(ValueError, match="upload_part_size_kb"):
            TransferConfig.from_dict({"upload_part_size_kb": part_size})

    @pytest.mark.parametrize(
        "key", ["upload_workers_big", "download_pieces_in_flight", "connection_pool_size"]
    )
    def test_rejects_non_positive_counts(self, key):
        with pytest.raises(ValueError, match=key):
            TransferConfig.from_dict({key: 0})

    def test_rejects_a_negative_cache_budget(self):
        with pytest.raises(ValueError, match="chunk_cache_mb"):
            TransferConfig.from_dict({"chunk_cache_mb": -1})

    def test_a_disabled_cache_is_allowed(self):
        assert TransferConfig.from_dict({"chunk_cache_mb": 0}).chunk_cache_mb == 0


class TestGithubRepoConfig:
    def test_from_dict(self):
        data = {"repo": "owner/repo", "commit": "main", "access_token": "token123"}
        config = GithubRepoConfig.from_dict(data)

        assert config.repo == "owner/repo"
        assert config.commit == "main"
        assert config.access_token == "token123"


class TestMetadataConfig:
    def test_from_dict_pinned_message(self):
        config = MetadataConfig.from_dict(
            MetadataConfigDict(type="pinned_message", name="name", github_repo=None)
        )

        assert config.type == MetadataType.PINNED_MESSAGE
        assert config.github_repo is None

    def test_from_dict_github_repo(self):
        config = MetadataConfig.from_dict(
            MetadataConfigDict(
                type="github_repo",
                name="name",
                github_repo={
                    "repo": "owner/repo",
                    "commit": "main",
                    "access_token": "token123",
                },
            )
        )

        assert config.type == MetadataType.GITHUB_REPO
        assert config.github_repo is not None
        assert config.github_repo.repo == "owner/repo"

    def test_from_dict_unknown_type(self):
        with pytest.raises(ValueError, match="Unknown metadata type: unknown_type"):
            MetadataConfig.from_dict(
                MetadataConfigDict(type="unknown_type", name="name", github_repo=None)
            )


class TestConfig:
    def test_from_dict(self):
        data = {
            "telegram": {
                "api_id": 12345,
                "api_hash": "hash123",
                "bot": {"token": "bot_token", "session_file": "bot.session"},
                "account": {"session_file": "account.session"},
                "login_timeout": 30000,
                "private_file_channel": 123456,
                "public_file_channel": 654321,
            },
            "tgfs": {
                "users": {},
                "jwt": {"secret": "jwt_secret", "algorithm": "HS256", "life": 3600},
                "server": {"host": "0.0.0.0", "port": 8080},
            },
        }
        config = Config.from_dict(data)

        assert config.telegram.api_id == 12345


class TestConfigFunctions:
    def test_get_config_loads_file(self, mocker):
        mock_open = mocker.patch("tgfs.config.open")
        mock_yaml_load = mocker.patch("tgfs.config.yaml.safe_load")
        mocker.patch("tgfs.config.__config", None)
        from tgfs.config import get_config

        mock_yaml_load.return_value = {
            "telegram": {
                "api_id": 12345,
                "api_hash": "hash123",
                "bot": {"token": "bot_token", "session_file": "bot.session"},
                "account": {"session_file": "account.session"},
                "login_timeout": 30000,
                "private_file_channel": 123456,
                "public_file_channel": 654321,
            },
            "tgfs": {
                "users": {},
                "jwt": {"secret": "jwt_secret", "algorithm": "HS256", "life": 3600},
                "server": {"host": "0.0.0.0", "port": 8080},
            },
        }

        config = get_config()

        mock_open.assert_called_once()
        mock_yaml_load.assert_called_once()
        assert config.telegram.api_id == 12345
