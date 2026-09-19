#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The match-register array a microcode body opens with.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class MatchRegisters:
    """
    An array of 32-bit match registers.
    """

    #: Width of one register, in bytes.
    REGISTER_SIZE: ClassVar[int] = 4
    #: Struct code for one register at :data:`REGISTER_SIZE`.
    _CODE: ClassVar[str] = "I"
    #: How many registers each family opens its body with.
    _COUNT_BY_FAMILY: ClassVar[dict[int, int]] = {
        0x0F: 8,
        0x10: 8,
        0x11: 8,
    }

    #: The registers, in order, as raw u32s. A slot not in use reads
    #: :attr:`unused_value`.
    #: Other names:
    #:   - Linux kernel: ``match_reg[8]``
    values: list[int]

    @property
    def count(self) -> int:
        """How many registers the array holds."""
        return len(self.values)

    @property
    def size(self) -> int:
        """Encoded size of the whole array, in bytes."""
        return self.count * self.REGISTER_SIZE

    @property
    def unused_value(self) -> int:
        """The value a slot not in use reads: all-ones at this width."""
        return (1 << (8 * self.REGISTER_SIZE)) - 1

    @property
    def used(self) -> list[int]:
        """The registers in use: the ROM addresses this patch actually takes over."""
        return [value for value in self.values if value != self.unused_value]

    @classmethod
    def count_for_family(cls, family: int) -> int:
        """How many match registers ``family`` opens its body with, 0 if unknown."""
        return cls._COUNT_BY_FAMILY.get(family, 0)

    @classmethod
    def for_family(cls, data: bytes, family: int) -> "MatchRegisters | None":
        """
        Parse the match registers ``family`` opens its body with from the start
        of ``data``, or ``None`` when its body does not begin with them.
        """
        count = cls.count_for_family(family)
        return cls.from_bytes(data, count) if count > 0 else None

    @classmethod
    def from_bytes(cls, data: bytes, count: int) -> "MatchRegisters":
        """
        Parse ``count`` registers from the start of ``data``. A buffer too short
        to hold them is malformed and refused.
        """
        needed = count * cls.REGISTER_SIZE
        if len(data) < needed:
            raise ValueError(
                f"not enough bytes for {count} match registers: "
                f"got {len(data)}, need {needed}"
            )
        return cls(values=list(struct.unpack_from(f"<{count}{cls._CODE}", data, 0)))

    def to_bytes(self) -> bytes:
        """Serialize the array back to its exact byte encoding."""
        return struct.pack(f"<{self.count}{self._CODE}", *self.values)
