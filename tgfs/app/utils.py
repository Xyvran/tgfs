from typing import Tuple

from tgfs.errors import TechnicalError


def strip_webdav_prefix(destination: str, client_name: str) -> str:
    """Turn a WebDAV ``Destination`` path into a client-relative path.

    The header carries the whole server path -- the ``/webdav`` mount point
    and the client name included -- while the ops layer works on paths
    relative to a single client's root.
    """
    prefix = f"/webdav/{client_name}"
    if destination == prefix:
        return ""
    if destination.startswith(f"{prefix}/"):
        return destination[len(prefix) :]
    return destination


def split_global_path(path: str) -> Tuple[str, str]:
    """
    Split a path into the client name and the sub path.
    Example:
        - Input: "notes-1/test/test.txt"
        - Output: ("notes-1", "test/test.txt")
    """
    if not path[0] == "/":
        path = f"/{path}"
    parts = path.split("/", 2)
    if len(parts) < 1:
        raise TechnicalError(f"Path must begin with a client name. Got: {path}")
    if len(parts) == 2:
        return parts[1], ""
    return parts[1], parts[2]
