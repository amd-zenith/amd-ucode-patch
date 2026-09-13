#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The build date: the first 32-bit word of the patch header (offset 0).

Known elsewhere as Linux ``data_code`` and the AMD patent's "date code".

It is a little-endian packed-BCD value laid out as ``0xMMDDYYYY``.
The high byte is the month, the next byte the day, and the low 16 bits the
four-digit year (e.g. the bytes ``07 20 14 06`` read as 2007-06-14).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.utils.bcd import decode_bcd, encode_bcd


@dataclass
class Date:
    """The 4-byte packed-BCD build date, decoded into editable fields."""

    #: Size of the date word.
    SIZE: ClassVar[int] = 4
    #: Struct layout: little-endian ``year (u16), day (u8), month (u8)``.
    _FMT: ClassVar[str] = "<HBB"
    #: Field widths, in BCD nibbles.
    _YEAR_NIBBLES: ClassVar[int] = 4
    _DAY_NIBBLES: ClassVar[int] = 2
    _MONTH_NIBBLES: ClassVar[int] = 2

    year: int
    month: int
    day: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "Date":
        """Parse a date from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for AMD date: got {len(data)}, need {cls.SIZE}"
            )
        raw_year, raw_day, raw_month = struct.unpack(cls._FMT, data[:cls.SIZE])
        return cls(
            year=decode_bcd(raw_year, cls._YEAR_NIBBLES),
            month=decode_bcd(raw_month, cls._MONTH_NIBBLES),
            day=decode_bcd(raw_day, cls._DAY_NIBBLES),
        )

    def to_bytes(self) -> bytes:
        """Serialize the date back to its packed-BCD byte encoding."""
        return struct.pack(
            self._FMT,
            encode_bcd(self.year, self._YEAR_NIBBLES),
            encode_bcd(self.day, self._DAY_NIBBLES),
            encode_bcd(self.month, self._MONTH_NIBBLES),
        )

    def __str__(self) -> str:
        return f"{self.year:04d}-{self.month:02d}-{self.day:02d}"
