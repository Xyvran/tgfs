import posixpath
from dataclasses import dataclass
from typing import Union

from tgfs.app.utils import split_global_path

BytesOrStr = Union[bytes, str]


@dataclass(frozen=True)
class ResolvedPath:
    """A client-scoped view of a path handed to us by an SFTP client.

    ``client_name`` is empty for the virtual root, the synthetic directory
    that lists one entry per configured Telegram client. ``relative`` is
    always ``Ops``-compatible: it starts with a slash and never ends with
    one, ``"/"`` denoting the root of that client.
    """

    client_name: str
    relative: str

    @property
    def is_root(self) -> bool:
        return not self.client_name

    @property
    def is_client_root(self) -> bool:
        return bool(self.client_name) and self.relative == "/"

    def child(self, name: str) -> "ResolvedPath":
        if self.is_root:
            return ResolvedPath(client_name=name, relative="/")
        prefix = "" if self.relative == "/" else self.relative
        return ResolvedPath(client_name=self.client_name, relative=f"{prefix}/{name}")

    @property
    def basename(self) -> str:
        if self.is_root:
            return "/"
        if self.relative == "/":
            return self.client_name
        return posixpath.basename(self.relative)

    def as_global(self) -> str:
        """Render the path the way the client sees it, e.g. ``/notes/a/b``."""
        if self.is_root:
            return "/"
        if self.relative == "/":
            return f"/{self.client_name}"
        return f"/{self.client_name}{self.relative}"


def decode(path: BytesOrStr) -> str:
    if isinstance(path, bytes):
        return path.decode("utf-8", "surrogateescape")
    return path


def normalize(path: BytesOrStr) -> str:
    """Collapse a client-supplied path into an absolute, slash-free-tail form.

    Relative paths are taken to be relative to the virtual root, and any
    ``..`` that would climb past it is clamped there, so a client cannot
    address anything outside the tree we publish.
    """
    decoded = decode(path).replace("\\", "/")
    normalized = posixpath.normpath(posixpath.join("/", decoded))
    if normalized == "//":
        # POSIX leaves a leading double slash alone; we do not want it.
        return "/"
    return normalized


def resolve(path: BytesOrStr) -> ResolvedPath:
    normalized = normalize(path)
    if normalized == "/":
        return ResolvedPath(client_name="", relative="/")

    client_name, sub_path = split_global_path(normalized)
    sub_path = sub_path.strip("/")
    return ResolvedPath(
        client_name=client_name,
        relative="/" if not sub_path else f"/{sub_path}",
    )
