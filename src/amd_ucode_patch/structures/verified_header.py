#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from dataclasses import dataclass



@dataclass
class VerifiedHeader:
    FMT = "<BB BB I"
    SIZE = struct.calcsize(FMT)

    autorun: int
    encrypted: int
    unk0: int
    unk1: int
    update_revision: int

    @staticmethod
    def from_bytes(buf: bytes) -> "VerifiedHeader":
        if len(buf) < VerifiedHeader.SIZE:
            raise ValueError("not enough bytes for AMD verified header")
        chunk = buf[0:VerifiedHeader.SIZE]
        vals = struct.unpack(VerifiedHeader.FMT, chunk)
        return VerifiedHeader(
            autorun=vals[0],
            encrypted=vals[1],
            unk0=vals[2],
            unk1=vals[3],
            update_revision=vals[4],
        )

    def to_bytes(self) -> bytes:
        return struct.pack(
            VerifiedHeader.FMT,
            self.autorun,
            self.encrypted,
            self.unk0,
            self.unk1,
            self.update_revision,
        )
