from typing import Optional

from pys3.app import create_app
from pys3.member import Member
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

    root = Folder("/", clients[client_name])

    if res := await root.member(sub_path.lstrip("/")):
        return res
    return None


def create_s3_app(clients: Clients, base_path: str = ""):
    for name, client in clients.items():
        cache = FSCache[Member]()
        cache.set("/", Folder("/", client))
        gfc[name] = cache

    return create_app(
        get_member=lambda path: _get_member(path, clients),
        base_path=base_path,
    )


__all__ = [
    "create_s3_app",
]
