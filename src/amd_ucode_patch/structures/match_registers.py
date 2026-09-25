#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The match-register array a microcode body opens with.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass(frozen=True)
class MatchRegisterLayout:
    """
    How one 32-bit match register packs the ROM addresses it names.
    """

    #: How many ROM addresses one register packs.
    addresses_per_register: int
    #: Width of one ROM address, in bits.
    address_bits: int
    #: Whether each address carries its own in-use flag, in the bit just above
    #: it. Where it does not, a free slot is marked by the address itself
    #: reading :data:`MatchRegisters.UNUSED_ADDRESS`.
    has_in_use_flag: bool

    @property
    def stride(self) -> int:
        """Bits one address occupies, including its in-use flag if it has one."""
        return self.address_bits + (1 if self.has_in_use_flag else 0)

    @property
    def address_mask(self) -> int:
        """Mask of one ROM address within the register."""
        return (1 << self.address_bits) - 1


#: One address per register, read from its low half, with a free slot reading
#: :data:`MatchRegisters.UNUSED_ADDRESS`. Used by families 0x0f-0x12.
SINGLE_ADDRESS = MatchRegisterLayout(
    addresses_per_register=1, address_bits=16, has_in_use_flag=False
)

#: Two 13-bit addresses per register, each followed by its in-use flag, and
#: four unused bits at the top. Used by the Zen families.
PACKED_ADDRESS_PAIR = MatchRegisterLayout(
    addresses_per_register=2, address_bits=13, has_in_use_flag=True
)


@dataclass
class MatchRegisters:
    """
    An array of 32-bit match registers.
    """

    #: Width of one register, in bytes.
    REGISTER_SIZE: ClassVar[int] = 4
    #: Struct code for one register at :data:`REGISTER_SIZE`.
    _CODE: ClassVar[str] = "I"
    #: The address a slot that is not in use reads, on the layouts that mark a
    #: free slot that way rather than with a flag.
    UNUSED_ADDRESS: ClassVar[int] = 0xFFFF
    #: How many registers each family opens its body with.
    _COUNT_BY_FAMILY: ClassVar[dict[int, int]] = {
        0x0F: 8,
        0x10: 8,
        0x11: 8,
        0x12: 8,
        0x17: 22,
        0x19: 38,
        0x1A: 60,
    }
    #: How each family packs one register. Every family in
    #: :data:`_COUNT_BY_FAMILY` appears here too.
    _LAYOUT_BY_FAMILY: ClassVar[dict[int, MatchRegisterLayout]] = {
        0x0F: SINGLE_ADDRESS,
        0x10: SINGLE_ADDRESS,
        0x11: SINGLE_ADDRESS,
        0x12: SINGLE_ADDRESS,
        0x17: PACKED_ADDRESS_PAIR,
        0x19: PACKED_ADDRESS_PAIR,
        0x1A: PACKED_ADDRESS_PAIR,
    }

    #: The registers, in order, as raw u32s.
    #: Other names:
    #:   - Linux kernel: ``match_reg[8]``
    #:   - zentool: ``match_t``
    values: list[int]
    #: How to read the addresses out of one register.
    layout: MatchRegisterLayout = field(default=SINGLE_ADDRESS)

    @property
    def count(self) -> int:
        """How many registers the array holds."""
        return len(self.values)

    @property
    def size(self) -> int:
        """Encoded size of the whole array, in bytes."""
        return self.count * self.REGISTER_SIZE

    @property
    def addresses(self) -> list[int]:
        """
        The ROM address each slot names, free slots included, in order. A
        register packs :attr:`MatchRegisterLayout.addresses_per_register` of
        them, so this is that many times as long as :attr:`values`.
        """
        return [address for value in self.values
                for address, _ in self._slots(value)]

    @property
    def used(self) -> list[int]:
        """The addresses in use: the ROM addresses this patch actually takes over."""
        return [address for value in self.values
                for address, in_use in self._slots(value) if in_use]

    def _slots(self, value: int) -> list[tuple[int, bool]]:
        """Each address one register packs, paired with whether it is in use."""
        slots = []
        for index in range(self.layout.addresses_per_register):
            shift = index * self.layout.stride
            address = (value >> shift) & self.layout.address_mask
            if self.layout.has_in_use_flag:
                in_use = bool((value >> (shift + self.layout.address_bits)) & 1)
            else:
                in_use = address != self.UNUSED_ADDRESS
            slots.append((address, in_use))
        return slots

    @classmethod
    def count_for_family(cls, family: int) -> int:
        """How many match registers ``family`` opens its body with, 0 if unknown."""
        return cls._COUNT_BY_FAMILY.get(family, 0)

    @classmethod
    def layout_for_family(cls, family: int) -> MatchRegisterLayout | None:
        """How ``family`` packs one register, or ``None`` when it carries none."""
        return cls._LAYOUT_BY_FAMILY.get(family)

    @classmethod
    def for_family(cls, data: bytes, family: int) -> "MatchRegisters | None":
        """
        Parse the match registers ``family`` opens its body with from the start
        of ``data``, or ``None`` when its body does not begin with them.
        """
        count = cls.count_for_family(family)
        if count <= 0:
            return None
        return cls.from_bytes(data, count, cls._LAYOUT_BY_FAMILY[family])

    @classmethod
    def from_bytes(cls, data: bytes, count: int,
                   layout: MatchRegisterLayout = SINGLE_ADDRESS) -> "MatchRegisters":
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
        return cls(
            values=list(struct.unpack_from(f"<{count}{cls._CODE}", data, 0)),
            layout=layout,
        )

    def to_bytes(self) -> bytes:
        """Serialize the array back to its exact byte encoding."""
        return struct.pack(f"<{self.count}{self._CODE}", *self.values)
