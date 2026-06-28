#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass
from .patch_header import PatchHeader
from .body import Body


@dataclass
class Patch:
    header: PatchHeader
    body: Body


    @staticmethod
    def from_bytes(buf: bytes) -> "Patch":
        header = PatchHeader.from_bytes(buf)
        # Everything after the header is the signed body: the verified header
        # (options + rev, Zen only) plus the microcode itself.
        body = Body.from_bytes(buf[header.size:], family=header.cpuid.family)
        return Patch(header=header, body=body)
