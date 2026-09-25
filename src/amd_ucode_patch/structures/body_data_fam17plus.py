#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Body data for the Zen families (0x17, 0x19 and 0x1a).
Their body opens with the match registers and continues with the micro-op quad
array.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.body_data import BodyData
from amd_ucode_patch.structures.match_registers import MatchRegisters
from amd_ucode_patch.structures.op_group_geometry import OpGroupGeometry


@dataclass
class BodyDataFam17Plus(BodyData):
    """
    The body data of a Zen patch.
    Used by families 0x17, 0x19 and 0x1a.
    """

    is_encrypted = False

    #: How this format lays out one micro-op quad.
    GEOMETRY: ClassVar[OpGroupGeometry] = OpGroupGeometry.for_family(0x17)

    #: The match registers the body opens with.
    #: Offset 0, :attr:`MatchRegisters.size` bytes.
    match_registers: MatchRegisters
    #: The micro-op quad array, as raw bytes: the region is known to be the
    #: patch's microcode, but the quads are not decoded into individual
    #: micro-ops yet.
    #: Offset :attr:`MatchRegisters.size`, the rest of the body.
    op_quads: bytes

    @classmethod
    def from_bytes(cls, data: bytes, family: int) -> "BodyDataFam17Plus":
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
                f"registers, so it has no Zen body data"
            )
        return cls(match_registers=registers, op_quads=data[registers.size:])

    @property
    def op_quad_count(self) -> int:
        """How many whole micro-op quads the array holds."""
        return self.GEOMETRY.group_count(len(self.op_quads))

    @property
    def holds_whole_quads(self) -> bool:
        """
        Whether the array divides exactly into quads, with no bytes left over.
        A real one always does; a short or padded array does not.
        """
        return self.GEOMETRY.holds_whole_groups(len(self.op_quads))

    def to_bytes(self) -> bytes:
        """Serialize the body data back to its exact byte encoding."""
        return self.match_registers.to_bytes() + self.op_quads
