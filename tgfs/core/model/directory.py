import datetime
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Self

from tgfs.errors import (
    FileOrDirectoryAlreadyExists,
    FileOrDirectoryDoesNotExist,
    InvalidPath,
    TechnicalError,
)
from tgfs.utils.time import FIRST_DAY_OF_EPOCH, ts

from .common import validate_name
from .serialized import TGFSDirectorySerialized, TGFSFileRefSerialized


@dataclass
class TGFSFileRef:
    message_id: int
    name: str
    location: "TGFSDirectory" = field(repr=False)

    # Mirror channel id (config string) -> message id of the file
    # descriptor copy in that channel. Empty when redundancy is off.
    mirrors: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> TGFSFileRefSerialized:
        res = TGFSFileRefSerialized(
            type="FR",
            messageId=self.message_id,
            name=self.name,
        )
        if self.mirrors:
            res["mirrors"] = self.mirrors
        return res

    def delete(self) -> None:
        self.location.delete_file_ref(self)


@dataclass
class TGFSDirectory:
    name: str
    parent: Optional["TGFSDirectory"]
    children: list["TGFSDirectory"] = field(default_factory=list)
    files: list[TGFSFileRef] = field(default_factory=list)
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    modified_at: datetime.datetime = field(default_factory=datetime.datetime.now)

    def __post_init__(self):
        validate_name(self.name)

    @property
    def created_at_timestamp(self) -> int:
        return ts(self.created_at)

    @property
    def modified_at_timestamp(self) -> int:
        return ts(self.modified_at)

    def _touch_modified(self) -> None:
        self.modified_at = datetime.datetime.now()

    def to_dict(self) -> TGFSDirectorySerialized:
        return TGFSDirectorySerialized(
            type="D",
            name=self.name,
            createdAt=self.created_at_timestamp,
            modifiedAt=self.modified_at_timestamp,
            children=[child.to_dict() for child in self.children],
            files=[file.to_dict() for file in self.files],
        )

    @staticmethod
    def from_dict(
        data: TGFSDirectorySerialized, parent: Optional["TGFSDirectory"] = None
    ) -> "TGFSDirectory":
        def _read_ts(value: int) -> datetime.datetime:
            if value > 0:
                return datetime.datetime.fromtimestamp(value / 1000)
            return FIRST_DAY_OF_EPOCH

        d = TGFSDirectory(
            name=data["name"],
            parent=parent,
            children=[],
            files=[],
            created_at=_read_ts(data.get("createdAt", 0) or 0),
            modified_at=_read_ts(data.get("modifiedAt", 0) or 0),
        )

        if data["files"]:
            d.files = [
                TGFSFileRef(
                    message_id=file["messageId"],
                    name=file["name"],
                    location=d,
                    mirrors={
                        str(channel): int(mid)
                        for channel, mid in (file.get("mirrors") or {}).items()
                    },
                )
                for file in data["files"]
                if file["name"] and file["messageId"]
            ]

        d.children = [TGFSDirectory.from_dict(child, d) for child in data["children"]]
        return d

    def create_dir(
        self, name: str, dir_to_copy: Optional["TGFSDirectory"]
    ) -> "TGFSDirectory":
        if len(self.find_dirs([name])) > 0:
            raise FileOrDirectoryAlreadyExists(name)

        child = TGFSDirectory(
            name=name,
            parent=self,
            children=[] if not dir_to_copy else dir_to_copy.children,
            files=[] if not dir_to_copy else dir_to_copy.files,
        )

        self.children.append(child)
        self._touch_modified()
        return child

    @classmethod
    def root_dir(cls) -> Self:
        return cls(name="root", parent=None)

    def find_dirs(self, names: Iterable[str] = tuple()) -> List["TGFSDirectory"]:
        if not names:
            return self.children
        return [child for child in self.children if child.name in frozenset(names)]

    def find_dir(self, name: str) -> "TGFSDirectory":
        dirs = self.find_dirs([name])
        if not dirs:
            raise FileOrDirectoryDoesNotExist(name)
        return dirs[0]

    def find_files(self, names: Iterable[str] = tuple()) -> List[TGFSFileRef]:
        if not names:
            return self.files
        return [file for file in self.files if file.name in frozenset(names)]

    def find_file(self, name: str) -> TGFSFileRef:
        files = self.find_files([name])
        if not files:
            raise FileOrDirectoryDoesNotExist(name)
        return files[0]

    def create_file_ref(self, name: str, fd_message_id: int) -> TGFSFileRef:
        if self.find_files([name]):
            raise FileOrDirectoryAlreadyExists(name)

        fr = TGFSFileRef(
            message_id=fd_message_id,
            name=name,
            location=self,
        )
        self.files.append(fr)
        self._touch_modified()
        return fr

    def delete_file_ref(self, fr: TGFSFileRef) -> None:
        self.files.remove(fr)
        self._touch_modified()

    def relocate_file_ref(
        self, fr: TGFSFileRef, to: "TGFSDirectory", new_name: Optional[str] = None
    ) -> TGFSFileRef:
        """Move ``fr`` to ``to``, keeping the Telegram messages behind it.

        A move must never touch the channel: the descriptor message and every
        content message stay exactly where they are, only the reference to
        them changes place. The new ref is created before the old one is
        dropped so a failing backend leaves the file reachable.
        """
        name = new_name or fr.name
        if to is self and name == fr.name:
            return fr

        moved = to.create_file_ref(name, fr.message_id)
        moved.mirrors = dict(fr.mirrors)
        try:
            self.delete_file_ref(fr)
        except Exception:
            to.delete_file_ref(moved)
            raise
        return moved

    def is_ancestor_of(self, other: "TGFSDirectory") -> bool:
        """True when ``other`` is ``self`` or lives somewhere below it."""
        node: Optional["TGFSDirectory"] = other
        while node is not None:
            if node is self:
                return True
            node = node.parent
        return False

    def move_to(
        self, new_parent: "TGFSDirectory", new_name: Optional[str] = None
    ) -> None:
        """Re-parent this directory (and everything below it) in place.

        Like :meth:`relocate_file_ref` this is a pure metadata operation --
        the subtree keeps pointing at the very same Telegram messages.
        """
        if self.parent is None:
            raise TechnicalError("The root directory cannot be moved")

        name = new_name or self.name
        validate_name(name)

        if new_parent is self.parent and name == self.name:
            return

        if self.is_ancestor_of(new_parent):
            raise InvalidPath(f"{self.absolute_path} cannot be moved into itself")

        if new_parent.find_dirs([name]):
            raise FileOrDirectoryAlreadyExists(name)

        old_parent = self.parent
        old_parent.children.remove(self)
        old_parent._touch_modified()

        self.name = name
        self.parent = new_parent
        new_parent.children.append(self)
        new_parent._touch_modified()

    def delete(self) -> None:
        if self.parent:
            self.parent.children.remove(self)
            self.parent._touch_modified()
        else:
            # root directory, just clear its contents
            self.children.clear()
            self.files.clear()
            self._touch_modified()

    @property
    def absolute_path(self) -> str:
        if self.parent is None:
            return ""
        return (
            f"{self.parent.absolute_path}/{self.name}"
            if self.name
            else self.parent.absolute_path
        )
