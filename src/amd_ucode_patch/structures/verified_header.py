#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from dataclasses import dataclass
from amd_ucode_patch.structures.patch_level import PatchLevel


@dataclass
class VerifiedHeader:
    # Fields before the trailing PatchLevel.
    FMT = "<BB BB"
    SIZE = struct.calcsize(FMT) + PatchLevel.SIZE

    autorun: int
    encrypted: int
    unk0: int
    unk1: int
    patch_level: PatchLevel

    @staticmethod
    def from_bytes(buf: bytes) -> "VerifiedHeader":
        if len(buf) < VerifiedHeader.SIZE:
            raise ValueError("not enough bytes for AMD verified header")
        head = struct.calcsize(VerifiedHeader.FMT)
        vals = struct.unpack(VerifiedHeader.FMT, buf[0:head])
        return VerifiedHeader(
            autorun=vals[0],
            encrypted=vals[1],
            unk0=vals[2],
            unk1=vals[3],
            patch_level=PatchLevel.from_bytes(buf[head:VerifiedHeader.SIZE]),
        )

    def to_bytes(self) -> bytes:
        return struct.pack(
            VerifiedHeader.FMT,
            self.autorun,
            self.encrypted,
            self.unk0,
            self.unk1,
        ) + self.patch_level.to_bytes()
