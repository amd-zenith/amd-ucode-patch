#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass
from .body_header import BodyHeader


#: Family at/after which the body carries a body header (options + rev).
#: This is the Zen boundary; kept independent of the signature gating.
BODY_HEADER_MIN_FAMILY = 0x17


@dataclass
class Body:
    """
    The signed portion of an AMD microcode patch -- the region the RSA signature
    in :class:`PatchHeader` covers (through the AES-CMAC).

    On Zen (signed) patches it is the ``options``/``rev`` block
    (:class:`BodyHeader`) followed by the match registers and the (encrypted)
    microcode opquads. On pre-Zen patches there is no body header and the
    whole thing is the raw, unsigned microcode.
    """

    body_header: BodyHeader | None
    data: bytes

    @staticmethod
    def from_bytes(buf: bytes, family: int | None = None) -> "Body":
        """
        Parse the body. The body header (options + rev) is present only on
        Zen patches (family >= ``BODY_HEADER_MIN_FAMILY``); ``family`` selects
        that. When ``family`` is unknown the body is treated as having none.
        """
        if family is not None and family >= BODY_HEADER_MIN_FAMILY:
            body_header = BodyHeader.from_bytes(buf, family=family)
            data = buf[BodyHeader.SIZE:]
        else:
            body_header = None
            data = buf
        return Body(body_header=body_header, data=data)

    def to_bytes(self) -> bytes:
        prefix = self.body_header.to_bytes() if self.body_header is not None else b""
        return prefix + self.data
