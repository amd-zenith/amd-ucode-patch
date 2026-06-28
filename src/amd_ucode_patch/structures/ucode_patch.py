#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass
from .patch_header import PatchHeader
from .verified_header import VerifiedHeader


@dataclass
class UcodePatch:
    header: PatchHeader
    signature: bytes
    public_key: bytes
    verified_header: VerifiedHeader | None
    body: bytes


    @staticmethod
    def from_bytes(buf: bytes) -> "UcodePatch":
        header = PatchHeader.from_bytes(buf)
        verified_header = None if header.cpuid.family < 0x16 else VerifiedHeader.from_bytes(buf[800::])
        body_start_pos = PatchHeader.SIZE + 256 + 512 + (0 if verified_header is None else VerifiedHeader.SIZE)
        return UcodePatch(
            header=header,
            signature=buf[PatchHeader.SIZE:PatchHeader.SIZE+256],
            public_key=buf[PatchHeader.SIZE+256:PatchHeader.SIZE+256+512],
            verified_header=verified_header,
            body=buf[body_start_pos::]
        )
