from typing import Dict, List, Literal, TypedDict


class TGFSFileVersionSerialized(TypedDict, total=False):
    type: Literal["FV"]
    id: str
    updatedAt: int
    messageId: int
    messageIds: List[int]
    size: int
    # Mirror channel id -> message ids of the forwarded copies of each
    # part, in the same order as messageIds. Absent when redundancy is
    # not in use, so pre-redundancy metadata parses unchanged.
    mirrors: Dict[str, List[int]]


class TGFSFileDescSerialized(TypedDict, total=False):
    type: Literal["F"]
    name: str
    versions: List[TGFSFileVersionSerialized]


class TGFSFileRefSerialized(TypedDict, total=False):
    type: Literal["FR"]
    messageId: int
    name: str
    # Mirror channel id -> message id of the file descriptor copy in
    # that channel. Absent when redundancy is not in use.
    mirrors: Dict[str, int]


class TGFSDirectorySerialized(TypedDict, total=False):
    type: Literal["D"]
    name: str
    createdAt: int
    modifiedAt: int
    children: List["TGFSDirectorySerialized"]
    files: List[TGFSFileRefSerialized]
