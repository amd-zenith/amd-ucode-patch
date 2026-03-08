#!/usr/bin/env python

import struct
from dataclasses import dataclass



@dataclass
class VerifiedHeader:
    FMT = "<BB BB I"
    SIZE = struct.calcsize(FMT)

    autorun: int
    encrypted: int
    update_revision: int

    @staticmethod
    def from_bytes(buf: bytes) -> "VerifiedHeader":
        if len(buf) < VerifiedHeader.SIZE:
            raise ValueError("not enough bytes for AMD header")
        chunk = buf[0:VerifiedHeader.SIZE]
        vals = struct.unpack(VerifiedHeader.FMT, chunk)
        return VerifiedHeader(
            autorun=vals[0],
            encrypted=vals[1],
            update_revision=vals[4],
        )
