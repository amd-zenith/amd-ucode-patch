#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Body data for Bobcat (0x14) and Bulldozer (0x15).

These families open their body with a 16-byte frame that ends in a copy of the
header's patch level. The frame sits inside the region the encrypted variants
encrypt, so it reads back only on a plaintext body -- which makes it a second,
structural opinion on whether a patch is encrypted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.body_data import BodyData
from amd_ucode_patch.structures.patch_level import PatchLevel


@dataclass
class BodyDataFam14to15(BodyData):
    """
    The body data of a Bobcat (0x14) or Bulldozer (0x15) patch.
    """

    is_encrypted = False

    #: Size of the frame the body opens with, up to and including the patch
    #: level.
    FRAME_SIZE: ClassVar[int] = 16
    #: Offset of the patch level within the frame.
    _PATCH_LEVEL_OFF: ClassVar[int] = 12

    #: Not modelled, kept verbatim.
    #: Offset 0, 12 bytes.
    unknown0: bytes
    #: A copy of the header's patch level.
    #: Offset 12, 4 bytes.
    patch_level: PatchLevel
    #: The microcode past the frame, kept verbatim and not yet modelled.
    #: Offset 16, the rest of the body.
    unknown1: bytes

    @classmethod
    def frame_is_readable(cls, data: bytes, patch_level: PatchLevel) -> bool:
        """
        Whether ``data`` opens with a frame that decodes for ``patch_level``:
        the word at offset 8 is zero and the patch level mirrors the header's.

        The frame is inside the encrypted region, so an encrypted body reads as
        ciphertext here and fails both halves. That makes this an independent
        check on the encrypted flag the header carries.
        """
        data = bytes(data)
        if len(data) < cls.FRAME_SIZE:
            return False
        reserved, mirror = struct.unpack_from("<II", data, 8)
        return reserved == 0 and mirror == patch_level.value

    @classmethod
    def from_bytes(cls, data: bytes, family: int) -> "BodyDataFam14to15":
        """
        Parse the body data from ``data`` for the given CPU ``family``.

        A body too short to hold the frame is malformed and is refused, as
        every other section does with a buffer it cannot fill.
        """
        data = bytes(data)
        if len(data) < cls.FRAME_SIZE:
            raise ValueError(
                f"not enough bytes for the family {family:#04x} body frame: "
                f"got {len(data)}, need {cls.FRAME_SIZE}"
            )
        return cls(
            unknown0=data[:cls._PATCH_LEVEL_OFF],
            patch_level=PatchLevel.from_bytes(data[cls._PATCH_LEVEL_OFF:]),
            unknown1=data[cls.FRAME_SIZE:],
        )

    def to_bytes(self) -> bytes:
        """Serialize the body data back to its exact byte encoding."""
        return self.unknown0 + self.patch_level.to_bytes() + self.unknown1
