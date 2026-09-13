#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The body header.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.patch_level import PatchLevel


@dataclass
class BodyHeader:
    """The 8-byte body header of a signed patch."""

    #: Size of the body header.
    SIZE: ClassVar[int] = 8
    #: Struct layout of the four leading bytes; the patch level follows.
    _FMT: ClassVar[str] = "<BBBB"
    #: Families whose body begins with a body header: Jaguar (0x16) and the Zen
    #: parts (0x17+). These are exactly the families with a signature slot.
    _FAMILIES: ClassVar[frozenset[int]] = frozenset({0x16, 0x17, 0x19, 0x1A})

    #: Whether the loader runs the patch immediately after loading it, instead
    #: of resuming normal operation. The same signal the pre-Zen header carries
    #: as its ``init_flag``.
    #: Offset 0, 1 byte.
    #: Other names:
    #:   - zentool: ``autorun``
    #:   - AMD patent US6438664B1: init flag
    init_flag: int
    #: Whether the microcode that follows is encrypted.
    #: Offset 1, 1 byte.
    #: Other names:
    #:   - zentool: ``encrypted``
    encrypted: int
    #: Unknown.
    #: Offset 2, 1 byte.
    #: Other names:
    #:   - zentool: ``unknown1``
    unknown1: int
    #: Unknown.
    #: Offset 3, 1 byte.
    #: Other names:
    #:   - zentool: ``unknown2``
    unknown2: int
    #: A copy of the header's patch level.
    #: Offset 4, 4 bytes.
    #: Other names:
    #:   - zentool: ``rev``
    patch_level: PatchLevel

    @classmethod
    def from_bytes(cls, data: bytes, family: int) -> "BodyHeader | None":
        """
        Parse the body header for ``family`` from the start of ``data``, or
        return ``None`` when the family carries no body header (or ``data`` is
        too short for one).
        """
        if family not in cls._FAMILIES or len(data) < cls.SIZE:
            return None
        init_flag, encrypted, unknown1, unknown2 = struct.unpack_from(cls._FMT, data, 0)
        return cls(
            init_flag=init_flag,
            encrypted=encrypted,
            unknown1=unknown1,
            unknown2=unknown2,
            patch_level=PatchLevel.from_bytes(data[struct.calcsize(cls._FMT):]),
        )

    def to_bytes(self) -> bytes:
        """Serialize the body header back to its exact byte encoding."""
        return struct.pack(
            self._FMT,
            self.init_flag,
            self.encrypted,
            self.unknown1,
            self.unknown2,
        ) + self.patch_level.to_bytes()
