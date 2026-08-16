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

    async def create(self, name: str, under: TGFSDirectory) -> TGFSDirectory:
        new_dir = under.create_dir(name)
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

    async def move(
        self,
        directory: TGFSDirectory,
        to_parent: TGFSDirectory,
        name: Optional[str] = None,
    ) -> TGFSDirectory:
        """Re-parent a directory instead of copying and deleting it.

        The subtree keeps referring to the same Telegram messages, so nothing
        is uploaded and, crucially, nothing is deleted from the channel.
        """
        directory.move_to(to_parent, name)
        await self.__metadata_api.push()
        return directory

    async def rm_dangerously(self, directory: TGFSDirectory) -> None:
        message_ids, mirror_ids = await self.__file_api.collect_deletable_message_ids(
            self.__subtree_file_refs(directory)
        )
        directory.delete()
        await self.__metadata_api.push()
        await self.__message_api.delete_messages(message_ids)
        await self.__file_api.delete_mirrored(mirror_ids)

    @classmethod
    def __subtree_file_refs(cls, directory: TGFSDirectory) -> List[TGFSFileRef]:
        frs = list(directory.find_files())
        for child in directory.find_dirs():
            frs.extend(cls.__subtree_file_refs(child))
        return frs
