import pytest
from tgfs.app.sftp.server import USER_INFO_KEY, TGFSSSHServer
from tgfs.auth.user import AdminUser, ReadonlyUser
from tgfs.errors.tgfs import LoginFailed


def build_config(mocker, users=None, authorized_keys_dir=None):
    config = mocker.Mock()
    config.tgfs.users = users if users is not None else {}
    config.tgfs.sftp.authorized_keys_dir = authorized_keys_dir
    return config


def build_server(mocker, config):
    server = TGFSSSHServer(config)
    conn = mocker.Mock()
    conn.get_extra_info = mocker.Mock(return_value=("10.0.0.1", 1234))
    server.connection_made(conn)
    return server, conn


def remembered_user(conn):
    conn.set_extra_info.assert_called_once()
    return conn.set_extra_info.call_args.kwargs[USER_INFO_KEY]


class TestBeginAuth:
    def test_requires_auth_when_users_are_configured(self, mocker):
        server, _ = build_server(
            mocker, build_config(mocker, users={"admin": mocker.Mock()})
        )

        assert server.begin_auth("admin") is True

    def test_grants_anonymous_readonly_access_without_users(self, mocker):
        server, conn = build_server(mocker, build_config(mocker, users={}))

        assert server.begin_auth("whoever") is False
        assert remembered_user(conn).readonly is True


class TestPasswordAuth:
    def test_is_offered(self, mocker):
        server, _ = build_server(mocker, build_config(mocker))

        assert server.password_auth_supported() is True

    def test_accepts_a_valid_password(self, mocker):
        mocker.patch(
            "tgfs.app.sftp.server.authenticate", return_value=AdminUser("admin")
        )
        server, conn = build_server(mocker, build_config(mocker))

        assert server.validate_password("admin", "secret") is True
        assert remembered_user(conn).username == "admin"

    def test_rejects_a_wrong_password(self, mocker):
        mocker.patch(
            "tgfs.app.sftp.server.authenticate", side_effect=LoginFailed("nope")
        )
        server, conn = build_server(mocker, build_config(mocker))

        assert server.validate_password("admin", "wrong") is False
        conn.set_extra_info.assert_not_called()

    def test_carries_the_readonly_flag(self, mocker):
        mocker.patch(
            "tgfs.app.sftp.server.authenticate", return_value=ReadonlyUser("viewer")
        )
        server, conn = build_server(mocker, build_config(mocker))

        assert server.validate_password("viewer", "secret") is True
        assert remembered_user(conn).readonly is True


class TestPublicKeyAuth:
    @pytest.fixture
    def key(self):
        import asyncssh

        return asyncssh.generate_private_key("ssh-ed25519")

    def test_is_not_offered_without_a_directory(self, mocker):
        server, _ = build_server(mocker, build_config(mocker))

        assert server.public_key_auth_supported() is False

    def test_is_offered_with_a_directory(self, mocker, tmp_path):
        server, _ = build_server(
            mocker, build_config(mocker, authorized_keys_dir=str(tmp_path))
        )

        assert server.public_key_auth_supported() is True

    def test_accepts_a_listed_key(self, mocker, tmp_path, key):
        (tmp_path / "admin").write_text(key.export_public_key().decode())
        config = build_config(
            mocker,
            users={"admin": mocker.Mock(readonly=False)},
            authorized_keys_dir=str(tmp_path),
        )
        server, conn = build_server(mocker, config)

        assert server.validate_public_key("admin", key.convert_to_public()) is True
        assert remembered_user(conn).readonly is False

    def test_rejects_an_unlisted_key(self, mocker, tmp_path, key):
        import asyncssh

        (tmp_path / "admin").write_text(key.export_public_key().decode())
        config = build_config(
            mocker,
            users={"admin": mocker.Mock(readonly=False)},
            authorized_keys_dir=str(tmp_path),
        )
        server, conn = build_server(mocker, config)

        other = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
        assert server.validate_public_key("admin", other) is False
        conn.set_extra_info.assert_not_called()

    def test_rejects_a_user_missing_from_the_config(self, mocker, tmp_path, key):
        (tmp_path / "ghost").write_text(key.export_public_key().decode())
        config = build_config(
            mocker, users={}, authorized_keys_dir=str(tmp_path)
        )
        server, _ = build_server(mocker, config)

        assert server.validate_public_key("ghost", key.convert_to_public()) is False

    def test_rejects_a_user_without_a_key_file(self, mocker, tmp_path, key):
        config = build_config(
            mocker,
            users={"admin": mocker.Mock(readonly=False)},
            authorized_keys_dir=str(tmp_path),
        )
        server, _ = build_server(mocker, config)

        assert server.validate_public_key("admin", key.convert_to_public()) is False

    def test_carries_the_readonly_flag(self, mocker, tmp_path, key):
        (tmp_path / "viewer").write_text(key.export_public_key().decode())
        config = build_config(
            mocker,
            users={"viewer": mocker.Mock(readonly=True)},
            authorized_keys_dir=str(tmp_path),
        )
        server, conn = build_server(mocker, config)

        assert server.validate_public_key("viewer", key.convert_to_public()) is True
        assert remembered_user(conn).readonly is True
