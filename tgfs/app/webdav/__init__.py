from typing import Optional

from asgidav.app import METHODS, create_app
from asgidav.member import Member
from tgfs.app.fs_cache import FSCache, gfc
from tgfs.app.utils import split_global_path
from tgfs.core import Clients

from .folder import Folder, RootFolder


async def _get_member(path: str, clients: Clients) -> Optional[Member]:
    if path == "" or path == "/":
        folders = {
            client_name: Folder("/", clients[client_name])
            for client_name in clients.keys()
        }
        return RootFolder(folders)

    client_name, sub_path = split_global_path(path)

    # Anything outside a configured file system (a browser asking for
    # /webdav/favicon.ico, a typo) is simply not found.
    if (client := clients.get(client_name)) is None:
        return None
    root = Folder("/", client)

    if res := await root.member(sub_path.lstrip("/")):
        return res
    return None


def create_webdav_app(clients: Clients, base_path: str = ""):
    for name, client in clients.items():
        cache = FSCache()
        cache.set("/", Folder("/", client))
        gfc[name] = cache

    return create_app(
        get_member=lambda path: _get_member(path, clients),
        base_path=base_path,
    )


__all__ = [
    "create_webdav_app",
    "METHODS",
]
