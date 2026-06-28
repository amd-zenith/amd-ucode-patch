#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass
from .patch_header import PatchHeader
from .verified_header import VerifiedHeader


@dataclass
class UcodePatch:
    header: PatchHeader
    verified_header: VerifiedHeader | None
    body: bytes


    @staticmethod
    def from_bytes(buf: bytes) -> "UcodePatch":
        header = PatchHeader.from_bytes(buf)
        # The verified header (options + rev) follows the signed header, and like
        # the signature block it only exists on Zen and later.
        if header.signature is not None:
            verified_header = VerifiedHeader.from_bytes(buf[header.size:], family=header.cpuid.family)
            body_start_pos = header.size + VerifiedHeader.SIZE
        else:
            verified_header = None
            body_start_pos = header.size
        return UcodePatch(
            header=header,
            verified_header=verified_header,
            body=buf[body_start_pos::]
        )
