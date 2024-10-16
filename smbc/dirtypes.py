import enum
import typing
from datetime import datetime
import operator
from functools import reduce


class Attribute(enum.IntFlag):
    """A convenience enumeration for manipulating SMB file attribute flags."""
    # description of flags mapping
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/65e0c225-5925-44b0-8104-6b91339c709f
    NONE = 0x0
    READ_ONLY = 0x01
    HIDDEN = 0x02
    SYSTEM = 0x04
    # Windows defines VOLUME_ID = 0x08, but CIFS/SMB doesn't
    DIRECTORY = 0x10
    ARCHIVE = 0x20
    # Windows defines DEVICE = 0x40, but CIFS/SMB doesn't
    NORMAL = 0x80
    TEMPORARY = 0x100
    SPARSE = 0x200
    REPARSE_POINT = 0x400
    COMPRESSED = 0x800
    OFFLINE = 0x1000
    NONINDEXED = 0x2000
    ENCRYPTED = 0x4000


AttributeMask = reduce(operator.or_, Attribute, Attribute.NONE)


class FileInfo(typing.NamedTuple):
    size: int
    attrs: Attribute
    uid: int
    gid: int
    btime: datetime
    mtime: datetime
    atime: datetime
    ctime: datetime
    name: str
    short_name: str

    @classmethod
    def from_raw_tuple(cls, rt):
        return FileInfo(
                rt[0],
                Attribute(rt[1]),
                rt[2],
                rt[3],
                datetime.fromtimestamp(rt[4]),
                datetime.fromtimestamp(rt[5]),
                datetime.fromtimestamp(rt[6]),
                datetime.fromtimestamp(rt[7]),
                rt[8],
                rt[9])


__all__ = ["Attribute", "AttributeMask", "FileInfo"]
