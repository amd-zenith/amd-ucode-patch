#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Body header for Zen 5 (0x1a).

Same 8-byte layout as the default body header, except that Zen 5 fills the two
bytes its predecessors leave zero (offset 2-3) with a copy of the header's loader
id. Verified across the whole corpus: on every family-0x1a patch the u16 there
equals the header's loader id, while every 0x16/0x17/0x19 patch leaves it zero.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.body_header import BodyHeader
from amd_ucode_patch.structures.loader_id import LoaderId
from amd_ucode_patch.structures.patch_level import PatchLevel


@dataclass
class BodyHeaderFam1a(BodyHeader):
    """The body header of a Zen 5 (0x1a) patch."""

    #: Struct layout of the two leading flag bytes; the loader id and patch level
    #: follow.
    _FMT: ClassVar[str] = "<BB"
    #: Offset of the loader-id copy (right after the two flag bytes).
    _LOADER_ID_OFF: ClassVar[int] = 2
    #: Offset of the patch-level copy (after the loader id).
    _PATCH_LEVEL_OFF: ClassVar[int] = 4

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
    #: A copy of the header's loader id (the u16 at header offset 8).
    #: Offset 2, 2 bytes. On family 0x1a this holds the header's loader id
    #: verbatim; the earlier signed families leave this span zero, which is why
    #: they model it as the two opaque bytes zentool calls ``unknown1`` and
    #: ``unknown2`` instead.
    loader_id: LoaderId
    #: A copy of the header's patch level.
    #: Offset 4, 4 bytes.
    #: Other names:
    #:   - zentool: ``rev``
    patch_level: PatchLevel

    @classmethod
    def from_bytes(cls, data: bytes) -> "BodyHeaderFam1a":
        """Parse the body header from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for the family-0x1a body header: "
                f"got {len(data)}, need {cls.SIZE}"
            )
        init_flag, encrypted = struct.unpack_from(cls._FMT, data, 0)
        return cls(
            init_flag=init_flag,
            encrypted=encrypted,
            loader_id=LoaderId.from_bytes(data[cls._LOADER_ID_OFF:]),
            patch_level=PatchLevel.from_bytes(data[cls._PATCH_LEVEL_OFF:]),
        )

    def to_bytes(self) -> bytes:
        """Serialize the body header back to its exact byte encoding."""
        return (
            struct.pack(self._FMT, self.init_flag, self.encrypted)
            + self.loader_id.to_bytes()
            + self.patch_level.to_bytes()
        )
