#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from dataclasses import dataclass

from amd_ucode_patch.utils.bcd import decode_bcd, encode_bcd, is_bcd


@dataclass
class PatchDate:
    """
    Build date stored in the first 32-bit word of an AMD microcode patch header.

    The field is a little-endian, packed binary-coded-decimal value laid out as
    0xMMDDYYYY: the high byte holds the month, the next byte the day, and the low
    16 bits the four-digit year (e.g. 0x12282021 decodes to 2021-12-28).
    """

    FMT = "<HBB"  # year (u16), day (u8), month (u8)
    SIZE = struct.calcsize(FMT)

    YEAR_NIBBLES = 4
    DAY_NIBBLES = 2
    MONTH_NIBBLES = 2
    NIBBLE_COUNT = YEAR_NIBBLES + DAY_NIBBLES + MONTH_NIBBLES

    # Loose calendar bounds, used only to reject obviously bogus values when
    # probing a file.
    MIN_YEAR = 1990
    MAX_YEAR = 2099

    year: int
    month: int
    day: int

    @staticmethod
    def from_bytes(buf: bytes) -> "PatchDate":
        if len(buf) < PatchDate.SIZE:
            raise ValueError("not enough bytes for AMD patch date")
        raw_year, raw_day, raw_month = struct.unpack(PatchDate.FMT, buf[0:PatchDate.SIZE])
        return PatchDate(
            year=decode_bcd(raw_year, PatchDate.YEAR_NIBBLES),
            day=decode_bcd(raw_day, PatchDate.DAY_NIBBLES),
            month=decode_bcd(raw_month, PatchDate.MONTH_NIBBLES),
        )

    def to_bytes(self) -> bytes:
        return struct.pack(
            PatchDate.FMT,
            encode_bcd(self.year, PatchDate.YEAR_NIBBLES),
            encode_bcd(self.day, PatchDate.DAY_NIBBLES),
            encode_bcd(self.month, PatchDate.MONTH_NIBBLES),
        )

    @staticmethod
    def is_valid_encoding(buf: bytes) -> bool:
        """
        Return ``True`` if ``buf`` holds well-formed packed BCD that decodes to a
        plausible calendar date. Intended as a lightweight signature check while
        deciding whether a file looks like a microcode patch.
        """
        if len(buf) < PatchDate.SIZE:
            return False
        raw_year, raw_day, raw_month = struct.unpack(PatchDate.FMT, buf[0:PatchDate.SIZE])
        if not (
            is_bcd(raw_year, PatchDate.YEAR_NIBBLES)
            and is_bcd(raw_day, PatchDate.DAY_NIBBLES)
            and is_bcd(raw_month, PatchDate.MONTH_NIBBLES)
        ):
            return False
        return PatchDate.from_bytes(buf).is_plausible()

    def is_plausible(self) -> bool:
        """Return ``True`` if the components fall within sane calendar ranges."""
        return (
            1 <= self.month <= 12
            and 1 <= self.day <= 31
            and PatchDate.MIN_YEAR <= self.year <= PatchDate.MAX_YEAR
        )

    def __str__(self) -> str:
        return f"{self.year:04d}-{self.month:02d}-{self.day:02d}"
