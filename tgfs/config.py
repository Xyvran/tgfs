import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Literal, Optional, Self, TypedDict

import yaml

logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get("TGFS_DATA_DIR", os.path.expanduser("~/.tgfs"))
CONFIG_FILE = os.environ.get("TGFS_CONFIG_FILE", "config.yaml")


@dataclass
class WebDAVConfig:
    host: str
    port: int
    path: str

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        return cls(host=data["host"], port=data["port"], path=data["path"])


@dataclass
class ManagerConfig:
    host: str
    port: int

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        return cls(host=data["host"], port=data["port"])


@dataclass
class UserConfig:
    password: str
    readonly: bool

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        return cls(password=data["password"], readonly=data.get("readonly", False))


@dataclass
class JWTConfig:
    secret: str
    algorithm: str
    life: int

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        return cls(
            secret=data["secret"], algorithm=data["algorithm"], life=data["life"]
        )


@dataclass
class EncryptionConfig:
    """Optional at-rest encryption settings.

    ``passphrase_env`` / ``passphrase`` / ``passphrase_file`` are mutually
    exclusive; the loader picks the first one that is set. A file containing
    the passphrase is the recommended option for systemd deployments (pair
    it with a ``LoadCredential=`` unit directive).

    ``master_salt_file`` stores the 16-byte master salt produced on the
    very first run. Back this up alongside your TGFS metadata -- without it
    the master key cannot be re-derived even with the correct passphrase.

    ``encrypt_names`` additionally replaces the Telegram-visible document
    name (and the pinned metadata document name) with an AES-GCM
    ciphertext blob, so a passive observer of the channel cannot read
    file or directory names from the document metadata. The plaintext
    name is still stored inside the TGFS metadata.json, which is itself
    encrypted at rest, so the WebDAV / manager UI is unaffected.
    """

    enabled: bool
    encrypt_names: bool
    passphrase: Optional[str]
    passphrase_env: Optional[str]
    passphrase_file: Optional[str]
    master_salt_file: str
    chunk_size: int

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "EncryptionConfig":
        if not data:
            return cls(
                enabled=False,
                encrypt_names=False,
                passphrase=None,
                passphrase_env=None,
                passphrase_file=None,
                master_salt_file=expand_path("master.salt"),
                chunk_size=64 * 1024,
            )
        return cls(
            enabled=bool(data.get("enabled", False)),
            encrypt_names=bool(data.get("encrypt_names", False)),
            passphrase=data.get("passphrase"),
            passphrase_env=data.get("passphrase_env"),
            passphrase_file=(
                expand_path(data["passphrase_file"])
                if data.get("passphrase_file")
                else None
            ),
            master_salt_file=expand_path(
                data.get("master_salt_file", "master.salt")
            ),
            chunk_size=int(data.get("chunk_size", 64 * 1024)),
        )

    def resolve_passphrase(self) -> str:
        """Return the passphrase from whichever source is configured.

        Raises :class:`ValueError` if encryption is enabled but no source
        was configured. Stripping a trailing newline makes the
        ``passphrase_file`` flow forgiving of editors that always add one.
        """
        if self.passphrase_env:
            value = os.environ.get(self.passphrase_env)
            if value is None:
                raise ValueError(
                    f"encryption passphrase env var '{self.passphrase_env}' not set"
                )
            return value
        if self.passphrase_file:
            with open(self.passphrase_file, "r", encoding="utf-8") as fh:
                return fh.read().rstrip("\n")
        if self.passphrase:
            return self.passphrase
        raise ValueError(
            "encryption enabled but no passphrase source configured "
            "(set one of passphrase, passphrase_env, passphrase_file)"
        )


@dataclass
class GithubRepoConfig:
    repo: str
    commit: str
    access_token: str

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        return cls(
            repo=data["repo"],
            commit=data["commit"],
            access_token=data["access_token"],
        )


class MetadataType(Enum):
    PINNED_MESSAGE = "pinned_message"
    GITHUB_REPO = "github_repo"


class MetadataConfigDict(TypedDict):
    name: str
    type: str
    github_repo: Optional[Dict]


@dataclass
class MetadataConfig:
    name: str
    type: MetadataType
    github_repo: Optional[GithubRepoConfig]

    @classmethod
    def from_dict(cls, data: MetadataConfigDict) -> Self:
        if (
            data.get("type", MetadataType.PINNED_MESSAGE.value)
            == MetadataType.PINNED_MESSAGE.value
        ):
            return cls(
                name=data.get("name", "default"),
                type=MetadataType.PINNED_MESSAGE,
                github_repo=None,
            )
        if data["type"] == MetadataType.GITHUB_REPO.value:
            if not (gh_repo_config := data.get("github_repo")):
                raise ValueError(
                    "GitHub repo configuration is required for GITHUB_REPO type"
                )
            return cls(
                name=data.get("name", "default"),
                type=MetadataType.GITHUB_REPO,
                github_repo=GithubRepoConfig.from_dict(gh_repo_config),
            )
        raise ValueError(
            f"Unknown metadata type: {data['type']}, available options: {', '.join(e.value for e in MetadataType)}"
        )


@dataclass
class ServerConfig:
    host: str
    port: int

    @classmethod
    def from_dict(cls, data: Dict) -> "ServerConfig":
        return cls(host=data["host"], port=data["port"])


@dataclass
class SFTPConfig:
    """Optional SFTP interface, served next to the HTTP/WebDAV surface.

    It exposes the very same virtual file tree and reuses ``tgfs.users``,
    so a readonly user stays readonly here as well. SSH cannot share the
    HTTP socket, hence the separate ``port``.

    ``host_key_file`` is created on first start (ed25519, mode 0600) when
    it is missing. Back it up: without it every restart presents a new
    host key and clients refuse to connect until their known_hosts entry
    is cleared.

    ``authorized_keys_dir`` optionally enables public key authentication.
    It holds one file per user, named after the username and written in
    the usual ``authorized_keys`` format. The user must still exist in
    ``tgfs.users`` so the readonly flag keeps applying.

    ``upload_buffer_size_mb`` is how much of an incoming upload is kept in
    memory before it spills over to ``upload_buffer_dir`` (the system temp
    directory when empty). SFTP never announces the file size up front
    while Telegram uploads need it, so a whole file has to be buffered
    before it can be sent.
    """

    enabled: bool
    host: str
    port: int
    host_key_file: str
    authorized_keys_dir: Optional[str]
    upload_buffer_size_mb: int
    upload_buffer_dir: Optional[str]

    DEFAULT_PORT = 2222
    DEFAULT_HOST_KEY_FILE = "sftp_host_key"
    DEFAULT_UPLOAD_BUFFER_SIZE_MB = 64

    @property
    def upload_buffer_size_bytes(self) -> int:
        return self.upload_buffer_size_mb * 1024 * 1024

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "SFTPConfig":
        data = data or {}

        port = int(data.get("port", cls.DEFAULT_PORT))
        if not 1 <= port <= 65535:
            raise ValueError(f"sftp.port must be between 1 and 65535, got {port}")

        buffer_size_mb = int(
            data.get("upload_buffer_size_mb", cls.DEFAULT_UPLOAD_BUFFER_SIZE_MB)
        )
        if buffer_size_mb < 0:
            raise ValueError(
                f"sftp.upload_buffer_size_mb must not be negative, got {buffer_size_mb}"
            )

        return cls(
            enabled=bool(data.get("enabled", False)),
            host=str(data.get("host", "0.0.0.0")),  # noqa: S104
            port=port,
            host_key_file=expand_path(
                data.get("host_key_file") or cls.DEFAULT_HOST_KEY_FILE
            ),
            authorized_keys_dir=(
                expand_path(data["authorized_keys_dir"])
                if data.get("authorized_keys_dir")
                else None
            ),
            upload_buffer_size_mb=buffer_size_mb,
            upload_buffer_dir=(
                expand_path(data["upload_buffer_dir"])
                if data.get("upload_buffer_dir")
                else None
            ),
        )


@dataclass
class TransferConfig:
    """Tuning knobs for moving file bytes to and from Telegram.

    Every value here used to be a constant in the code. The right setting
    depends on how many bots a deployment has, how much bandwidth it can
    use and how tolerant its account is of Telegram's rate limits, so none
    of them has a single good answer.

    Downloads are split into pieces of ``download_piece_size_kb`` and
    ``download_pieces_in_flight`` of them are fetched at once. Output must
    stay in order, so a finished piece waits for its turn: peak buffering
    per download is the product of the two -- 16 MiB at the defaults.
    Raising either speeds up a single large download and costs memory per
    concurrent reader.

    ``connection_pool_size`` is how many MTProto connections each bot
    opens. One connection serialises its requests, so a deployment with a
    single bot token gains the most here; with several bots the pieces
    already spread across them.

    ``chunk_cache_mb`` is the memory budget for caching downloaded bytes;
    ``0`` disables the cache. ``chunk_cache_block_kb`` is the unit it caches
    in: a read of a few kilobytes pulls a whole block, so a larger block
    serves more of the reads that follow and wastes more on the ones that
    jump around.
    """

    upload_workers_small: int
    upload_workers_big: int
    upload_part_size_kb: int
    download_piece_size_kb: int
    download_pieces_in_flight: int
    parallel_download_threshold_mb: int
    connection_pool_size: int
    chunk_cache_mb: int
    chunk_cache_readahead: int
    chunk_cache_block_kb: int

    DEFAULT_UPLOAD_WORKERS_SMALL = 3
    DEFAULT_UPLOAD_WORKERS_BIG = 8
    # 512 KiB is the largest part Telegram accepts and is valid for any file
    # size, so there is no reason to send the smaller parts the library
    # would otherwise pick for files below 750 MB.
    DEFAULT_UPLOAD_PART_SIZE_KB = 512
    DEFAULT_DOWNLOAD_PIECE_SIZE_KB = 4096
    DEFAULT_DOWNLOAD_PIECES_IN_FLIGHT = 4
    DEFAULT_PARALLEL_DOWNLOAD_THRESHOLD_MB = 10
    DEFAULT_CONNECTION_POOL_SIZE = 1
    DEFAULT_CHUNK_CACHE_MB = 0
    DEFAULT_CHUNK_CACHE_READAHEAD = 2
    DEFAULT_CHUNK_CACHE_BLOCK_KB = 1024

    @property
    def download_piece_size_bytes(self) -> int:
        return self.download_piece_size_kb * 1024

    @property
    def upload_part_size_bytes(self) -> int:
        return self.upload_part_size_kb * 1024

    @property
    def parallel_download_threshold_bytes(self) -> int:
        return self.parallel_download_threshold_mb * 1024 * 1024

    @property
    def chunk_cache_bytes(self) -> int:
        return self.chunk_cache_mb * 1024 * 1024

    @property
    def chunk_cache_block_bytes(self) -> int:
        return self.chunk_cache_block_kb * 1024

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "TransferConfig":
        data = data or {}

        def positive(key: str, default: int) -> int:
            value = int(data.get(key, default))
            if value < 1:
                raise ValueError(f"transfer.{key} must be at least 1, got {value}")
            return value

        def non_negative(key: str, default: int) -> int:
            value = int(data.get(key, default))
            if value < 0:
                raise ValueError(f"transfer.{key} must not be negative, got {value}")
            return value

        part_size = positive("upload_part_size_kb", cls.DEFAULT_UPLOAD_PART_SIZE_KB)
        # Telegram only accepts part sizes that divide 512 KiB, and it caps
        # them there; anything else is rejected for every part of the file.
        if part_size > 512 or 512 % part_size != 0:
            raise ValueError(
                "transfer.upload_part_size_kb must divide 512 and not exceed it, "
                f"got {part_size}"
            )

        return cls(
            upload_workers_small=positive(
                "upload_workers_small", cls.DEFAULT_UPLOAD_WORKERS_SMALL
            ),
            upload_workers_big=positive(
                "upload_workers_big", cls.DEFAULT_UPLOAD_WORKERS_BIG
            ),
            upload_part_size_kb=part_size,
            download_piece_size_kb=positive(
                "download_piece_size_kb", cls.DEFAULT_DOWNLOAD_PIECE_SIZE_KB
            ),
            download_pieces_in_flight=positive(
                "download_pieces_in_flight", cls.DEFAULT_DOWNLOAD_PIECES_IN_FLIGHT
            ),
            parallel_download_threshold_mb=positive(
                "parallel_download_threshold_mb",
                cls.DEFAULT_PARALLEL_DOWNLOAD_THRESHOLD_MB,
            ),
            connection_pool_size=positive(
                "connection_pool_size", cls.DEFAULT_CONNECTION_POOL_SIZE
            ),
            chunk_cache_mb=non_negative("chunk_cache_mb", cls.DEFAULT_CHUNK_CACHE_MB),
            chunk_cache_readahead=non_negative(
                "chunk_cache_readahead", cls.DEFAULT_CHUNK_CACHE_READAHEAD
            ),
            chunk_cache_block_kb=positive(
                "chunk_cache_block_kb", cls.DEFAULT_CHUNK_CACHE_BLOCK_KB
            ),
        )


@dataclass
class TGFSConfig:
    users: dict[str, UserConfig]
    jwt: JWTConfig
    metadata: Dict[str, MetadataConfig]
    server: ServerConfig
    encryption: EncryptionConfig
    sftp: SFTPConfig
    transfer: TransferConfig

    @classmethod
    def from_dict(cls, data: Dict) -> Self:
        metadata_config: Dict[str, MetadataConfigDict] = data.get("metadata", {})

        return cls(
            users=(
                {
                    username: UserConfig.from_dict(user)
                    for username, user in data["users"].items()
                }
                if data["users"]
                else {}
            ),
            jwt=JWTConfig.from_dict(data["jwt"]),
            metadata={
                k: MetadataConfig.from_dict(v) for k, v in metadata_config.items()
            },
            server=ServerConfig.from_dict(data["server"]),
            encryption=EncryptionConfig.from_dict(data.get("encryption")),
            sftp=SFTPConfig.from_dict(data.get("sftp")),
            transfer=TransferConfig.from_dict(data.get("transfer")),
        )


def expand_path(path: str) -> str:
    return os.path.expanduser(os.path.join(DATA_DIR, path)).replace("/", os.path.sep)


@dataclass
class BotConfig:
    token: str
    session_file: str
    tokens: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "BotConfig":
        return cls(
            token=data.get("token", ""),
            tokens=data.get("tokens", []),
            session_file=expand_path(data["session_file"]),
        )


@dataclass
class AccountConfig:
    session_file: str
    used_to_upload: bool
    used_to_download: bool

    @classmethod
    def from_dict(cls, data: dict) -> "AccountConfig":
        return cls(
            session_file=expand_path(data["session_file"]),
            used_to_upload=data.get("used_to_upload", False),
            used_to_download=data.get("used_to_download", False),
        )


@dataclass
class RedundancyConfig:
    """RAID-1-style mirroring of file channels.

    ``mirrors`` maps a primary channel id (as listed in
    ``private_file_channel``) to the channel ids of its mirrors. Every
    file part uploaded to the primary is copied to each mirror --
    server-side via message forwarding in ``forward`` mode (no
    re-upload bandwidth), or by downloading and re-uploading in
    ``reupload`` mode (for channels with "restrict saving content"
    enabled, where forwarding is impossible).

    With ``strict: false`` (the default) a failed mirror write is
    logged and the upload still succeeds; the backfill task can close
    the gap later. With ``strict: true`` the upload fails.
    """

    mirrors: Dict[str, List[str]]
    mode: Literal["forward", "reupload"]
    strict: bool

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> Optional["RedundancyConfig"]:
        if not data:
            return None
        raw_mirrors = data.get("mirrors") or {}
        mirrors: Dict[str, List[str]] = {}
        for primary, mirror_ids in raw_mirrors.items():
            if not mirror_ids:
                continue
            mirror_list = [str(m) for m in mirror_ids]
            if str(primary) in mirror_list:
                raise ValueError(
                    f"Channel {primary} cannot be configured as its own mirror"
                )
            if len(set(mirror_list)) != len(mirror_list):
                raise ValueError(
                    f"Duplicate mirror channel for primary channel {primary}"
                )
            mirrors[str(primary)] = mirror_list
        if not mirrors:
            return None
        mode = data.get("mode", "forward")
        if mode not in ("forward", "reupload"):
            raise ValueError(
                f"Unknown redundancy mode: {mode}, available options: forward, reupload"
            )
        return cls(
            mirrors=mirrors,
            mode=mode,
            strict=bool(data.get("strict", False)),
        )


@dataclass
class TelegramConfig:
    api_id: int
    api_hash: str
    account: Optional[AccountConfig]
    bot: BotConfig
    private_file_channel: List[str]
    lib: Literal["pyrogram", "telethon"]
    delete_messages_on_remove: bool
    redundancy: Optional[RedundancyConfig]

    @classmethod
    def from_dict(cls, data: dict) -> "TelegramConfig":
        return cls(
            api_id=data["api_id"],
            api_hash=data["api_hash"],
            account=(
                AccountConfig.from_dict(data["account"]) if "account" in data else None
            ),
            bot=BotConfig.from_dict(data["bot"]),
            private_file_channel=data["private_file_channel"],
            lib=data.get("lib") or "telethon",
            delete_messages_on_remove=bool(
                data.get("delete_messages_on_remove", False)
            ),
            redundancy=RedundancyConfig.from_dict(data.get("redundancy")),
        )


@dataclass
class Config:
    telegram: TelegramConfig
    tgfs: TGFSConfig

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        return cls(
            telegram=TelegramConfig.from_dict(data["telegram"]),
            tgfs=TGFSConfig.from_dict(data["tgfs"]),
        )


__config_file_path = expand_path(os.path.join(DATA_DIR, CONFIG_FILE))
__config: Config | None = None


def _load_config(file_path: str) -> Config:
    with open(file_path, "r") as file:
        data = yaml.safe_load(file)
        return Config.from_dict(data)


def get_config() -> Config:
    global __config
    if __config is None:
        logger.info(f"Using configuration file: {__config_file_path}")
        __config = _load_config(__config_file_path)
    return __config
