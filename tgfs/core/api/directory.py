from typing import List, Optional

from tgfs.core.model import TGFSDirectory, TGFSFileRef
from tgfs.errors import DirectoryIsNotEmpty, FileOrDirectoryDoesNotExist

from .file import FileApi
from .message import MessageApi
from .metadata import MetaDataApi


class DirectoryApi:
    def __init__(
        self,
        metadata_api: MetaDataApi,
        file_api: FileApi,
        message_api: MessageApi,
    ):
        self.__metadata_api = metadata_api
        self.__file_api = file_api
        self.__message_api = message_api

    @property
    def root(self):
        return self.__metadata_api.get_root_directory()

    async def create(
        self,
        name: str,
        under: TGFSDirectory,
        dir_to_copy: Optional[TGFSDirectory] = None,
    ) -> TGFSDirectory:
        new_dir = under.create_dir(name, dir_to_copy)
        await self.__metadata_api.push()
        return new_dir

    @staticmethod
    def ls(directory: TGFSDirectory) -> List[TGFSDirectory | TGFSFileRef]:
        return directory.find_dirs() + directory.find_files()

    @staticmethod
    def get_fr(directory: TGFSDirectory, file_name: str) -> TGFSFileRef:
        if f := directory.find_file(file_name):
            return f
        raise FileOrDirectoryDoesNotExist(file_name)

    async def rm_empty(self, directory: TGFSDirectory) -> None:
        if directory.find_dirs() or directory.find_files():
            raise DirectoryIsNotEmpty(directory.absolute_path)
        await self.rm_dangerously(directory)

    async def rm_dangerously(self, directory: TGFSDirectory) -> None:
        message_ids, mirror_ids = await self.__collect_subtree_message_ids(directory)
        directory.delete()
        await self.__metadata_api.push()
        await self.__message_api.delete_messages(message_ids)
        await self.__file_api.delete_mirrored(mirror_ids)

    async def __collect_subtree_message_ids(
        self, directory: TGFSDirectory
    ) -> tuple[List[int], dict[str, List[int]]]:
        ids: List[int] = []
        mirror_ids: dict[str, List[int]] = {}
        for fr in directory.find_files():
            fr_ids, fr_mirror_ids = await self.__file_api.collect_all_message_ids(fr)
            ids.extend(fr_ids)
            for channel_key, channel_ids in fr_mirror_ids.items():
                mirror_ids.setdefault(channel_key, []).extend(channel_ids)
        for child in directory.find_dirs():
            child_ids, child_mirror_ids = await self.__collect_subtree_message_ids(
                child
            )
            ids.extend(child_ids)
            for channel_key, channel_ids in child_mirror_ids.items():
                mirror_ids.setdefault(channel_key, []).extend(channel_ids)
        return ids, mirror_ids
