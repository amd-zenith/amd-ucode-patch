#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Signature block for family 0x16 (Jaguar).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.signature import Signature


@dataclass
class SignatureFam16(Signature):
    """The 576-byte family 0x16 signature-slot block, kept verbatim."""

    #: Total size of the block.
    SIZE: ClassVar[int] = 576

    #: The block, not decoded (its internal structure is unknown).
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignatureFam16":
        """Parse the block from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for the fam 0x16 signature block: "
                f"got {len(data)}, need {cls.SIZE}"
            )
        return cls(data=bytes(data[:cls.SIZE]))

    def to_bytes(self) -> bytes:
        """Serialize the block back to its exact byte encoding."""
        return self.data
