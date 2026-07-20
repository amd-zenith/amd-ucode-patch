#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from dataclasses import dataclass
from amd_ucode_patch.structures.patch_level import PatchLevel


@dataclass
class BodyHeader:
    """
    Body header of a Zen (family >= 0x17) AMD microcode patch.

    Layout (offsets from the start of the body)::

        offset 0  autorun    u8   auto-run flag (0 / 1)
        offset 1  encrypted  u8   set when the instruction body is encrypted (0 / 1)
        offset 2  unknown1   u8   unknown; zero on Zen1-Zen4, non-zero on Zen5
        offset 3  unknown2   u8   unknown; zero on Zen1-Zen4, 0x80 on Zen5
        offset 4  patch_level  u32  patch level; mirrors the header patch_id
    """
    # Fields before the trailing PatchLevel.
    FMT = "<BB BB"
    SIZE = struct.calcsize(FMT) + PatchLevel.SIZE

    autorun: int
    encrypted: int
    #: Unknown byte at offset 2; zero on Zen1-Zen4, non-zero on Zen5.
    unknown1: int
    #: Unknown byte at offset 3; zero on Zen1-Zen4, 0x80 on Zen5.
    unknown2: int
    patch_level: PatchLevel

    @staticmethod
    def from_bytes(buf: bytes, family: int | None = None) -> "BodyHeader":
        if len(buf) < BodyHeader.SIZE:
            raise ValueError("not enough bytes for AMD body header")
        head = struct.calcsize(BodyHeader.FMT)
        vals = struct.unpack(BodyHeader.FMT, buf[0:head])
        return BodyHeader(
            autorun=vals[0],
            encrypted=vals[1],
            unknown1=vals[2],
            unknown2=vals[3],
            patch_level=PatchLevel.from_bytes(buf[head:BodyHeader.SIZE], family=family),
        )

    def to_bytes(self) -> bytes:
        return struct.pack(
            BodyHeader.FMT,
            self.autorun,
            self.encrypted,
            self.unknown1,
            self.unknown2,
        ) + self.patch_level.to_bytes()
