#!/usr/bin/env python

from dataclasses import dataclass
from .ucode_patch_header import UcodePatchHeader


@dataclass
class UcodePatch:
    header: UcodePatchHeader
    signature: bytes
    public_key: bytes


    @staticmethod
    def from_bytes(buf: bytes) -> "UcodePatch":
        header = UcodePatchHeader.from_bytes(buf)
        return UcodePatch(
            header=header,
            signature=buf[32:288],
            public_key=buf[288:800],
        )
