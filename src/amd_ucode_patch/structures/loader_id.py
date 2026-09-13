#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The loader id: the u16 at header offset 8.

Linux ``mc_patch_data_id``, zentool ``format``, AMD patent "MPB ID".
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class LoaderId:
    """The 2-byte loader / patch-format id, as an editable little-endian u16."""

    #: Size of the loader-id field.
    SIZE: ClassVar[int] = 2
    #: Struct layout: little-endian u16.
    _FMT: ClassVar[str] = "<H"

    value: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "LoaderId":
        """Parse a loader id from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for AMD loader id: got {len(data)}, need {cls.SIZE}"
            )
        (value,) = struct.unpack_from(cls._FMT, data, 0)
        return cls(value=value)

    def to_bytes(self) -> bytes:
        """Serialize the loader id back to its exact byte encoding."""
        return struct.pack(self._FMT, self.value)

    def __int__(self) -> int:
        return self.value

    def __str__(self) -> str:
        return f"{self.value:04x}"
