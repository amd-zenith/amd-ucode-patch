#!/usr/bin/env python

from dataclasses import dataclass
from .ucode_patch_header import UcodePatchHeader


@dataclass
class UcodePatch:
    header: UcodePatchHeader

    @staticmethod
    def from_bytes(buf: bytes) -> "UcodePatch":
        header = UcodePatchHeader.from_bytes(buf)
        return UcodePatch(
            header,
        )
