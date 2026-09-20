#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Body data for family 0x12 and older.
Used by K8/K10/Griffin/Llano (families 0f/10/11/12), whose body opens with the
match registers and continues with the micro-op triad array.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.body_data import BodyData
from amd_ucode_patch.structures.match_registers import MatchRegisters


@dataclass
class BodyDataFam0fto12(BodyData):
    """
    The body data of a family 0x12-or-older patch.
    Used by K8/K10/Griffin/Llano (families 0f/10/11/12).
    """

    is_encrypted = False

    #: Size of one micro-op, in bytes.
    OP_SIZE: ClassVar[int] = 8
    #: Micro-ops per triad.
    OPS_PER_TRIAD: ClassVar[int] = 3
    #: Size of the sequence control word that ends a triad, in bytes.
    SEQUENCE_WORD_SIZE: ClassVar[int] = 4
    #: Encoded size of one triad: three micro-ops and a sequence control word.
    OP_TRIAD_SIZE: ClassVar[int] = OPS_PER_TRIAD * OP_SIZE + SEQUENCE_WORD_SIZE

    #: The match registers the body opens with.
    #: Offset 0, :attr:`MatchRegisters.size` bytes.
    match_registers: MatchRegisters
    #: The micro-op triad array, as raw bytes: the region is known to be the
    #: patch's microcode, but the triads are not decoded into individual
    #: micro-ops yet. The header's ``op_triad_count`` counts the triads here
    #: and its ``op_triad_checksum`` sums them.
    #: Offset :attr:`MatchRegisters.size`, the rest of the body.
    op_triads: bytes

    @classmethod
    def from_bytes(cls, data: bytes, family: int) -> "BodyDataFam0fto12":
        """
        Parse the body data from ``data`` for the given CPU ``family``.

        A body too short to hold the match registers its family declares is
        malformed and is refused, as every other section does with a buffer it
        cannot fill.
        """
        data = bytes(data)
        registers = MatchRegisters.for_family(data, family)
        if registers is None:
            raise ValueError(
                f"family {family:#04x} does not open its body with match "
                f"registers, so it has no family-0x12-or-older body data"
            )
        return cls(match_registers=registers, op_triads=data[registers.size:])

    @property
    def op_triad_count(self) -> int:
        """
        How many whole micro-op triads the array holds. The header records this
        same count, so the two disagreeing means the array is not the length
        the header claims.
        """
        return len(self.op_triads) // self.OP_TRIAD_SIZE

    @property
    def holds_whole_triads(self) -> bool:
        """
        Whether the array divides exactly into triads, with no bytes left over.
        A real one always does; a short or padded array does not.
        """
        return len(self.op_triads) % self.OP_TRIAD_SIZE == 0

    @property
    def op_triad_checksum(self) -> int:
        """
        The u32 sum of the micro-op triad array, truncated to 32 bits. The
        header records this same value, so the two disagreeing means the patch
        data did not survive intact.

        Raises :class:`ValueError` if the array is not a whole number of u32
        words, which a real triad array always is.
        """
        if len(self.op_triads) % 4:
            raise ValueError(
                f"micro-op triad array is not a whole number of u32 words: "
                f"{len(self.op_triads)} bytes"
            )
        words = struct.unpack(f"<{len(self.op_triads) // 4}I", self.op_triads)
        return sum(words) & 0xFFFFFFFF

    def to_bytes(self) -> bytes:
        """Serialize the body data back to its exact byte encoding."""
        return self.match_registers.to_bytes() + self.op_triads
