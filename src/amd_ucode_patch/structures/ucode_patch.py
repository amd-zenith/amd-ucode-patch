#!/usr/bin/env python

from dataclasses import dataclass
from .ucode_patch_header import UcodePatchHeader
from .verified_header import VerifiedHeader


@dataclass
class UcodePatch:
    header: UcodePatchHeader
    signature: bytes
    public_key: bytes
    verified_header: VerifiedHeader
    body: bytes


    @staticmethod
    def from_bytes(buf: bytes) -> "UcodePatch":
        return UcodePatch(
            header=UcodePatchHeader.from_bytes(buf),
            signature=buf[32:288],
            public_key=buf[288:800],
            verified_header=VerifiedHeader.from_bytes(buf[800::]),
            body=buf[800+VerifiedHeader.SIZE::]
        )
