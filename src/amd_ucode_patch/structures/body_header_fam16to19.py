#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Body header for the signed families that leave offset 2-3 zero.

Jaguar (0x16), Zen 1-2 (0x17) and Zen 3-4 (0x19) all carry the 8-byte body
header but leave the two bytes between the flags and the patch-level copy
unmodelled; across the corpus they are always zero. Zen 5 (0x1a) fills that span
instead, and gets :class:`BodyHeaderFam1a`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.body_header import BodyHeader
from amd_ucode_patch.structures.patch_level import PatchLevel


@dataclass
class BodyHeaderFam16to19(BodyHeader):
    """The body header of a signed patch on families 0x16, 0x17 and 0x19."""

    #: Struct layout of the four leading bytes; the patch level follows.
    _FMT: ClassVar[str] = "<BBBB"

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
    def from_bytes(cls, data: bytes) -> "BodyHeaderFam16to19":
        """Parse the body header from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for the body header: got {len(data)}, "
                f"need {cls.SIZE}"
            )
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
