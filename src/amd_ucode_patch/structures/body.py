#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass
from .verified_header import VerifiedHeader


#: Family at/after which the body carries a verified header (options + rev).
#: This is the Zen boundary; kept independent of the signature gating.
VERIFIED_HEADER_MIN_FAMILY = 0x17


@dataclass
class Body:
    """
    The signed portion of an AMD microcode patch -- the region the RSA signature
    in :class:`PatchHeader` covers (through the AES-CMAC).

    On Zen (signed) patches it is the ``options``/``rev`` block
    (:class:`VerifiedHeader`) followed by the match registers and the (encrypted)
    microcode opquads. On pre-Zen patches there is no verified header and the
    whole thing is the raw, unsigned microcode.
    """

    verified_header: VerifiedHeader | None
    data: bytes

    @staticmethod
    def from_bytes(buf: bytes, family: int | None = None) -> "Body":
        """
        Parse the body. The verified header (options + rev) is present only on
        Zen patches (family >= ``VERIFIED_HEADER_MIN_FAMILY``); ``family`` selects
        that. When ``family`` is unknown the body is treated as having none.
        """
        if family is not None and family >= VERIFIED_HEADER_MIN_FAMILY:
            verified_header = VerifiedHeader.from_bytes(buf, family=family)
            data = buf[VerifiedHeader.SIZE:]
        else:
            verified_header = None
            data = buf
        return Body(verified_header=verified_header, data=data)

    def to_bytes(self) -> bytes:
        prefix = self.verified_header.to_bytes() if self.verified_header is not None else b""
        return prefix + self.data
