import asyncio
import functools
import logging
import os.path
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    List,
    Optional,
    TypeVar,
    Union,
    cast,
)

import asyncssh
from asyncssh import SFTPAttrs, SFTPName
from asyncssh.constants import (
    ACE4_APPEND_DATA,
    ACE4_READ_DATA,
    ACE4_WRITE_DATA,
    FXF_ACCESS_DISPOSITION,
    FXF_APPEND,
    FXF_APPEND_DATA,
    FXF_CREAT,
    FXF_CREATE_NEW,
    FXF_CREATE_TRUNCATE,
    FXF_EXCL,
    FXF_OPEN_OR_CREATE,
    FXF_READ,
    FXF_TRUNC,
    FXF_TRUNCATE_EXISTING,
    FXF_WRITE,
)

from tgfs.auth.basic import authenticate
from tgfs.auth.user import AdminUser, ReadonlyUser, User
from tgfs.config import Config
from tgfs.core import Client, Clients, Ops
from tgfs.core.model import TGFSDirectory
from tgfs.errors import (
    DirectoryIsNotEmpty,
    FileOrDirectoryAlreadyExists,
    FileOrDirectoryDoesNotExist,
    InvalidName,
    InvalidPath,
)
from tgfs.utils.time import ts

from .attrs import dir_attrs, file_attrs, root_attrs
from .handles import ReadHandle, WriteHandle
from .paths import ResolvedPath, normalize, resolve

logger = logging.getLogger(__name__)

# The connection-level key under which the authenticated user is stashed so
# the SFTP session -- created later, per channel -- can pick it up again.
USER_INFO_KEY = "tgfs_user"

T = TypeVar("T")


def _to_sftp_error(ex: Exception) -> asyncssh.SFTPError:
    if isinstance(ex, FileOrDirectoryDoesNotExist):
        return asyncssh.SFTPNoSuchFile(str(ex))
    if isinstance(ex, FileOrDirectoryAlreadyExists):
        return asyncssh.SFTPFailure(str(ex))
    if isinstance(ex, DirectoryIsNotEmpty):
        return asyncssh.SFTPFailure(str(ex))
    if isinstance(ex, (InvalidName, InvalidPath)):
        return asyncssh.SFTPFailure(str(ex))
    logger.exception("Unexpected error while serving an SFTP request")
    return asyncssh.SFTPFailure(str(ex) or ex.__class__.__name__)


def translate_errors(
    func: Callable[..., Awaitable[T]],
) -> Callable[..., Awaitable[T]]:
    """Turn TGFS exceptions into the SFTP status codes clients understand."""

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> T:
        try:
            return await func(*args, **kwargs)
        except asyncssh.SFTPError:
            raise
        except Exception as ex:
            raise _to_sftp_error(ex) from ex

    return wrapper


class TGFSSSHServer(asyncssh.SSHServer):
    """Authenticates SSH connections against the very same users as WebDAV.

    Password authentication goes through :func:`tgfs.auth.basic.authenticate`,
    so the ``readonly`` flag and the anonymous fallback behave exactly as
    they do over HTTP. Public key authentication is only offered when an
    ``authorized_keys_dir`` is configured, and the user still has to be
    listed in ``tgfs.users`` so the readonly flag keeps applying.
    """

    def __init__(self, config: Config):
        self._config = config
        self._conn: Optional[asyncssh.SSHServerConnection] = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.debug("SFTP connection lost: %s", exc)

    def begin_auth(self, username: str) -> bool:
        if not self._config.tgfs.users:
            # No users configured means anonymous read-only access, the same
            # deal the HTTP side offers.
            self._remember(ReadonlyUser("anonymous"))
            return False
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        try:
            user = authenticate(username, password)
        except Exception as ex:
            logger.info("SFTP password authentication failed for %s: %s", username, ex)
            return False
        self._remember(user)
        return True

    def public_key_auth_supported(self) -> bool:
        return bool(self._config.tgfs.sftp.authorized_keys_dir)

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        user = self._user_from_config(username)
        if user is None:
            return False

        authorized_keys = self._load_authorized_keys(username)
        if authorized_keys is None:
            return False

        client_addr = self._client_addr()
        if authorized_keys.validate(key, "", client_addr) is None:
            logger.info("SFTP public key rejected for %s", username)
            return False

        self._remember(user)
        return True

    def _remember(self, user: User) -> None:
        if self._conn is not None:
            self._conn.set_extra_info(**{USER_INFO_KEY: user})

    def _client_addr(self) -> str:
        if self._conn is None:
            return ""
        peername = self._conn.get_extra_info("peername")
        return str(peername[0]) if peername else ""

    def _user_from_config(self, username: str) -> Optional[User]:
        user_cfg = self._config.tgfs.users.get(username)
        if user_cfg is None:
            return None
        return ReadonlyUser(username) if user_cfg.readonly else AdminUser(username)

    def _load_authorized_keys(
        self, username: str
    ) -> Optional[asyncssh.SSHAuthorizedKeys]:
        directory = self._config.tgfs.sftp.authorized_keys_dir
        if not directory:
            return None

        # The username is a config key, never a client-supplied string, but
        # keep it to a bare filename anyway so no path can be traversed.
        path = os.path.join(directory, os.path.basename(username))
        try:
            return asyncssh.read_authorized_keys(path)
        except (OSError, ValueError) as ex:
            logger.info("No usable authorized_keys for %s (%s): %s", username, path, ex)
            return None


class TGFSSFTPServer(asyncssh.SFTPServer):
    """Serves the TGFS tree over SFTP.

    The layout matches the WebDAV one exactly: the root is a synthetic
    directory holding one entry per configured client, and everything below
    it is that client's tree. Both interfaces go through :class:`Ops`, so
    encryption, mirroring and task tracking behave identically here.
    """

    def __init__(self, chan: asyncssh.SSHServerChannel, clients: Clients, config: Config):
        super().__init__(chan)
        self._clients = clients
        self._config = config
        self._user: User = chan.get_extra_info(USER_INFO_KEY) or ReadonlyUser(
            "anonymous"
        )
        self._handles: List[Union[ReadHandle, WriteHandle]] = []

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @property
    def _readonly(self) -> bool:
        return self._user.readonly

    def _require_write(self) -> None:
        if self._readonly:
            raise asyncssh.SFTPPermissionDenied(
                "You do not have permission to perform this action"
            )

    def _client(self, name: str) -> Client:
        try:
            return self._clients[name]
        except KeyError:
            raise asyncssh.SFTPNoSuchFile(f"No such client: {name}") from None

    def _ops(self, resolved: ResolvedPath) -> Ops:
        return Ops(self._client(resolved.client_name))

    def _dir(self, resolved: ResolvedPath) -> TGFSDirectory:
        client = self._client(resolved.client_name)
        if resolved.is_client_root:
            return client.dir_api.root
        return Ops(client).cd(resolved.relative)

    async def _file_attrs(self, resolved: ResolvedPath) -> SFTPAttrs:
        client = self._client(resolved.client_name)
        fd = await Ops(client).desc(resolved.relative)
        fv = fd.get_latest_version()
        # The content repository reports the logical size: with encryption on
        # that is the plaintext length, which is what the client will get.
        size = await client.fc_repo.content_length(fv)
        return file_attrs(
            size=size,
            created_ms=ts(fd.created_at),
            modified_ms=fv.updated_at_timestamp,
            readonly=self._readonly,
        )

    def _dir_entry_attrs(self, directory: TGFSDirectory) -> SFTPAttrs:
        return dir_attrs(
            created_ms=directory.created_at_timestamp,
            modified_ms=directory.modified_at_timestamp,
            readonly=self._readonly,
        )

    async def _attrs_of(self, resolved: ResolvedPath) -> SFTPAttrs:
        if resolved.is_root:
            return root_attrs(self._readonly)
        try:
            return self._dir_entry_attrs(self._dir(resolved))
        except FileOrDirectoryDoesNotExist:
            pass
        return await self._file_attrs(resolved)

    # ------------------------------------------------------------------
    # metadata
    # ------------------------------------------------------------------

    def realpath(self, path: bytes) -> bytes:
        return normalize(path).encode("utf-8", "surrogateescape")

    @translate_errors
    async def stat(self, path: bytes) -> SFTPAttrs:
        return await self._attrs_of(resolve(path))

    @translate_errors
    async def lstat(self, path: bytes) -> SFTPAttrs:
        # There are no symlinks in this filesystem, so lstat is just stat.
        return await self._attrs_of(resolve(path))

    @translate_errors
    async def fstat(self, file_obj: object) -> SFTPAttrs:
        if isinstance(file_obj, ReadHandle):
            return file_attrs(file_obj.size, 0, 0, self._readonly)
        if isinstance(file_obj, WriteHandle):
            return file_attrs(file_obj.size, 0, 0, self._readonly)
        raise asyncssh.SFTPInvalidHandle("Invalid file handle")

    def setstat(self, path: bytes, attrs: SFTPAttrs) -> None:
        # Ownership, modes and timestamps are not stored. Refusing here would
        # abort otherwise fine transfers -- `sftp put` and rsync set them on
        # every upload -- so accept and ignore, as the WebDAV side does.
        self._require_write()

    def fsetstat(self, file_obj: object, attrs: SFTPAttrs) -> None:
        self._require_write()

    def statvfs(self, path: bytes) -> asyncssh.SFTPVFSAttrs:
        return self._vfs_attrs()

    def fstatvfs(self, file_obj: object) -> asyncssh.SFTPVFSAttrs:
        return self._vfs_attrs()

    @staticmethod
    def _vfs_attrs() -> asyncssh.SFTPVFSAttrs:
        # Telegram imposes no meaningful quota we could report, but clients
        # do ask before uploading, so answer with a plausible, roomy volume.
        block_size = 4096
        blocks = 1 << 40
        return asyncssh.SFTPVFSAttrs(
            bsize=block_size,
            frsize=block_size,
            blocks=blocks,
            bfree=blocks,
            bavail=blocks,
            files=1 << 30,
            ffree=1 << 30,
            favail=1 << 30,
            fsid=0,
            flags=0,
            namemax=255,
        )

    def readlink(self, path: bytes) -> bytes:
        raise asyncssh.SFTPOpUnsupported("Symbolic links are not supported")

    def symlink(self, oldpath: bytes, newpath: bytes) -> None:
        raise asyncssh.SFTPOpUnsupported("Symbolic links are not supported")

    def link(self, oldpath: bytes, newpath: bytes) -> None:
        raise asyncssh.SFTPOpUnsupported("Hard links are not supported")

    # ------------------------------------------------------------------
    # directory listing
    # ------------------------------------------------------------------

    async def scandir(self, path: bytes) -> AsyncIterator[SFTPName]:
        try:
            resolved = resolve(path)
            entries = await self._list(resolved)
        except asyncssh.SFTPError:
            raise
        except Exception as ex:
            raise _to_sftp_error(ex) from ex

        for entry in entries:
            yield entry

    async def _list(self, resolved: ResolvedPath) -> List[SFTPName]:
        if resolved.is_root:
            here = root_attrs(self._readonly)
            entries = [self._name(".", here), self._name("..", here)]
            for name, client in self._clients.items():
                entries.append(
                    self._name(name, self._dir_entry_attrs(client.dir_api.root))
                )
            return entries

        directory = self._dir(resolved)
        here = self._dir_entry_attrs(directory)
        entries = [self._name(".", here), self._name("..", here)]

        for sub in directory.find_dirs():
            entries.append(self._name(sub.name, self._dir_entry_attrs(sub)))

        file_refs = directory.find_files()
        attrs = await asyncio.gather(
            *(self._file_attrs(resolved.child(fr.name)) for fr in file_refs),
            return_exceptions=True,
        )
        for file_ref, attr in zip(file_refs, attrs):
            if isinstance(attr, BaseException):
                # A single unreadable descriptor must not blank out the whole
                # listing; show the entry with an unknown size instead.
                logger.warning(
                    "Could not read metadata of %s: %s",
                    resolved.child(file_ref.name).as_global(),
                    attr,
                )
                attr = file_attrs(0, 0, 0, self._readonly)
            entries.append(self._name(file_ref.name, cast(SFTPAttrs, attr)))

        return entries

    @staticmethod
    def _name(filename: str, attrs: SFTPAttrs) -> SFTPName:
        return SFTPName(
            filename=filename.encode("utf-8", "surrogateescape"), attrs=attrs
        )

    # ------------------------------------------------------------------
    # file access
    # ------------------------------------------------------------------

    @translate_errors
    async def open(self, path: bytes, pflags: int, attrs: SFTPAttrs) -> object:
        resolved = resolve(path)
        if resolved.is_root or resolved.is_client_root or self._is_dir(resolved):
            raise asyncssh.SFTPFailure(f"{resolved.as_global()} is a directory")

        if pflags & (FXF_WRITE | FXF_APPEND):
            return await self._open_for_write(resolved, pflags)
        return await self._open_for_read(resolved)

    @translate_errors
    async def open56(
        self, path: bytes, desired_access: int, flags: int, attrs: SFTPAttrs
    ) -> object:
        # SFTPv5+ replaced pflags with an access mask plus a disposition.
        # Fold it back so there is a single open implementation.
        return await self.open(path, _pflags_from_v56(desired_access, flags), attrs)

    async def _open_for_read(self, resolved: ResolvedPath) -> ReadHandle:
        client = self._client(resolved.client_name)
        ops = Ops(client)
        fd = await ops.desc(resolved.relative)
        size = await client.fc_repo.content_length(fd.get_latest_version())
        handle = ReadHandle(
            ops=ops,
            path=resolved.relative,
            name=resolved.basename,
            size=size,
        )
        self._handles.append(handle)
        return handle

    async def _open_for_write(self, resolved: ResolvedPath, pflags: int) -> WriteHandle:
        self._require_write()

        if pflags & FXF_APPEND:
            raise asyncssh.SFTPOpUnsupported(
                "Appending to an existing file is not supported"
            )

        ops = Ops(self._client(resolved.client_name))
        exists = await self._exists(ops, resolved)

        if exists and pflags & FXF_EXCL:
            raise asyncssh.SFTPFailure(f"{resolved.as_global()} already exists")
        if not exists and not pflags & FXF_CREAT:
            raise asyncssh.SFTPNoSuchFile(f"{resolved.as_global()} does not exist")

        # Reserve the name right away so a listing during the upload shows it,
        # exactly like the WebDAV PUT path does.
        await ops.touch(resolved.relative)

        sftp_cfg = self._config.tgfs.sftp
        handle = WriteHandle(
            ops=ops,
            path=resolved.relative,
            spool_max_bytes=sftp_cfg.upload_buffer_size_bytes,
            spool_dir=sftp_cfg.upload_buffer_dir,
        )
        self._handles.append(handle)
        return handle

    def _is_dir(self, resolved: ResolvedPath) -> bool:
        try:
            self._dir(resolved)
        except FileOrDirectoryDoesNotExist:
            return False
        return True

    @staticmethod
    async def _exists(ops: Ops, resolved: ResolvedPath) -> bool:
        try:
            ops.stat_file(resolved.relative)
        except FileOrDirectoryDoesNotExist:
            return False
        return True

    @translate_errors
    async def read(self, file_obj: object, offset: int, size: int) -> bytes:
        if not isinstance(file_obj, ReadHandle):
            raise asyncssh.SFTPFailure("File is not open for reading")
        return await file_obj.read(offset, size)

    @translate_errors
    async def write(self, file_obj: object, offset: int, data: bytes) -> int:
        self._require_write()
        if not isinstance(file_obj, WriteHandle):
            raise asyncssh.SFTPFailure("File is not open for writing")
        await file_obj.write(offset, data)
        return len(data)

    @translate_errors
    async def close(self, file_obj: object) -> None:
        if not isinstance(file_obj, (ReadHandle, WriteHandle)):
            return
        try:
            await file_obj.close()
        finally:
            if file_obj in self._handles:
                self._handles.remove(file_obj)

    # ------------------------------------------------------------------
    # mutations
    # ------------------------------------------------------------------

    @translate_errors
    async def mkdir(self, path: bytes, attrs: SFTPAttrs) -> None:
        self._require_write()
        resolved = resolve(path)
        if resolved.is_root or resolved.is_client_root:
            raise asyncssh.SFTPPermissionDenied(
                "Clients are configured, not created over SFTP"
            )
        await self._ops(resolved).mkdir(resolved.relative, parents=False)

    @translate_errors
    async def rmdir(self, path: bytes) -> None:
        self._require_write()
        resolved = resolve(path)
        if resolved.is_root or resolved.is_client_root:
            raise asyncssh.SFTPPermissionDenied(
                "Clients are configured, not removed over SFTP"
            )
        await self._ops(resolved).rm_dir(resolved.relative, recursive=False)

    @translate_errors
    async def remove(self, path: bytes) -> None:
        self._require_write()
        resolved = resolve(path)
        if resolved.is_root or resolved.is_client_root:
            raise asyncssh.SFTPPermissionDenied("Cannot remove a client root")
        await self._ops(resolved).rm_file(resolved.relative)

    @translate_errors
    async def rename(self, oldpath: bytes, newpath: bytes) -> None:
        await self._rename(oldpath, newpath)

    @translate_errors
    async def posix_rename(self, oldpath: bytes, newpath: bytes) -> None:
        await self._rename(oldpath, newpath)

    async def _rename(self, oldpath: bytes, newpath: bytes) -> None:
        self._require_write()
        source, target = resolve(oldpath), resolve(newpath)

        if source.is_root or source.is_client_root:
            raise asyncssh.SFTPPermissionDenied("Cannot rename a client root")
        if target.is_root or target.is_client_root:
            raise asyncssh.SFTPFailure("Cannot overwrite a client root")
        if source.client_name != target.client_name:
            raise asyncssh.SFTPOpUnsupported(
                "Moving between clients is not supported"
            )

        ops = self._ops(source)
        try:
            ops.cd(source.relative)
        except FileOrDirectoryDoesNotExist:
            await ops.mv_file(source.relative, target.relative)
        else:
            await ops.mv_dir(source.relative, target.relative)

    # ------------------------------------------------------------------
    # session teardown
    # ------------------------------------------------------------------

    async def exit(self) -> None:
        # Anything still open was not closed by the client, so the transfer
        # was cut short: drop buffered uploads rather than committing a
        # truncated file.
        handles, self._handles = self._handles, []
        for handle in handles:
            try:
                if isinstance(handle, WriteHandle):
                    await handle.abort()
                else:
                    await handle.close()
            except Exception as ex:  # pragma: no cover - best effort cleanup
                logger.debug("Failed to clean up an SFTP handle: %s", ex)


def _pflags_from_v56(desired_access: int, flags: int) -> int:
    pflags = 0
    if desired_access & ACE4_READ_DATA:
        pflags |= FXF_READ
    if desired_access & (ACE4_WRITE_DATA | ACE4_APPEND_DATA):
        pflags |= FXF_WRITE
    if desired_access & ACE4_APPEND_DATA or flags & FXF_APPEND_DATA:
        pflags |= FXF_APPEND

    disposition = flags & FXF_ACCESS_DISPOSITION
    if disposition == FXF_CREATE_NEW:
        pflags |= FXF_CREAT | FXF_EXCL
    elif disposition == FXF_CREATE_TRUNCATE:
        pflags |= FXF_CREAT | FXF_TRUNC
    elif disposition == FXF_OPEN_OR_CREATE:
        pflags |= FXF_CREAT
    elif disposition == FXF_TRUNCATE_EXISTING:
        pflags |= FXF_TRUNC

    return pflags


def make_sftp_factory(
    clients: Clients, config: Config
) -> Callable[[asyncssh.SSHServerChannel], TGFSSFTPServer]:
    def factory(chan: asyncssh.SSHServerChannel) -> TGFSSFTPServer:
        return TGFSSFTPServer(chan, clients, config)

    return factory


def make_server_factory(config: Config) -> Callable[[], TGFSSSHServer]:
    def factory() -> TGFSSSHServer:
        return TGFSSSHServer(config)

    return factory


__all__ = [
    "TGFSSFTPServer",
    "TGFSSSHServer",
    "make_server_factory",
    "make_sftp_factory",
]
