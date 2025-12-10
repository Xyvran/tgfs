import asyncio
import datetime
import email.utils
from abc import ABC, abstractmethod
from enum import Enum
from typing import Literal, TypedDict


class ResourceType(Enum):
    DEFAULT = ""
    COLLECTION = "collection"


PropertyName = Literal[
    "getlastmodified", "creationdate", "displayname", "resourcetype", "getcontenttype"
]


class Properties(TypedDict, total=False):
    getlastmodified: str
    creationdate: str
    displayname: str
    resourcetype: str
    getcontenttype: str


class Member(ABC):
    resource_type: ResourceType = ResourceType.DEFAULT

    def __init__(self, path: str):
        self.path = path
        self.is_hidden = False
        self.is_readonly = False
        self.is_root = False

    @abstractmethod
    async def content_type(self) -> str:
        pass

    @abstractmethod
    async def content_length(self) -> int:
        raise NotImplementedError

    @abstractmethod
    async def display_name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def creation_date(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def last_modified(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def remove(self) -> None:
        raise NotImplementedError

    @abstractmethod
    async def copy_to(self, destination: str) -> None:
        raise NotImplementedError

    @abstractmethod
    async def move_to(self, destination: str) -> None:
        raise NotImplementedError

    async def get_properties(self) -> Properties:
        lastmodified, creationdate, displayname, contenttype = await asyncio.gather(
            self.last_modified(),
            self.creation_date(),
            self.display_name(),
            self.content_type(),
        )

        return Properties(
            getlastmodified=lastmodified,
            creationdate=creationdate,
            displayname=displayname,
            resourcetype=self.resource_type.value,
            getcontenttype=contenttype,
        )
