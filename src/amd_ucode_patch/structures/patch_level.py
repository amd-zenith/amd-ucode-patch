#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from dataclasses import dataclass


@dataclass
class PatchLevel:
    """
    Microcode patch level (a.k.a. patch ID / update revision), stored as the
    second 32-bit word of an AMD microcode patch header (`patch_id`).

    This is the value the CPU reports via ``rdmsr 0x8B`` and the one the kernel
    compares before applying a patch, so it is meaningful as a whole word.
    """

    FMT = "<I"
    SIZE = struct.calcsize(FMT)

    value: int

    @staticmethod
    def from_bytes(buf: bytes) -> "PatchLevel":
        if len(buf) < PatchLevel.SIZE:
            raise ValueError("not enough bytes for AMD patch level")
        (value,) = struct.unpack(PatchLevel.FMT, buf[0:PatchLevel.SIZE])
        return PatchLevel(value=value)

    def to_bytes(self) -> bytes:
        return struct.pack(PatchLevel.FMT, self.value)

    def __int__(self) -> int:
        return self.value

    def __str__(self) -> str:
        return f"{self.value:08x}"
