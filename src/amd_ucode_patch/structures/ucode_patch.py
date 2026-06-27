#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass
from .ucode_patch_header import UcodePatchHeader
from .verified_header import VerifiedHeader


@dataclass
class UcodePatch:
    header: UcodePatchHeader
    signature: bytes
    public_key: bytes
    verified_header: VerifiedHeader | None
    body: bytes


    @staticmethod
    def from_bytes(buf: bytes) -> "UcodePatch":
        header = UcodePatchHeader.from_bytes(buf)
        verified_header = None if header.cpuid.family < 0x16 else VerifiedHeader.from_bytes(buf[800::])
        body_start_pos = UcodePatchHeader.SIZE + 256 + 512 + (0 if verified_header is None else VerifiedHeader.SIZE)
        return UcodePatch(
            header=header,
            signature=buf[UcodePatchHeader.SIZE:UcodePatchHeader.SIZE+256],
            public_key=buf[UcodePatchHeader.SIZE+256:UcodePatchHeader.SIZE+256+512],
            verified_header=verified_header,
            body=buf[body_start_pos::]
        )
