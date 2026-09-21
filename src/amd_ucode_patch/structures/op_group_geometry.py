#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
How a format lays out one microcode operation group.

Microcode is stored as a repeating group: a fixed number of micro-ops followed
by a sequence control word that says where execution goes next.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OpGroupGeometry:
    """
    The layout of one operation group, in bytes.
    """

    #: Size of one micro-op.
    op_size: int
    #: Micro-ops per group.
    ops_per_group: int
    #: Size of the sequence control word that ends the group.
    sequence_word_size: int

    @classmethod
    def for_family(cls, family: int) -> "OpGroupGeometry | None":
        """
        The group geometry ``family`` uses, or ``None`` when it is not known.
        """
        return _BY_FAMILY.get(family)

    @property
    def group_size(self) -> int:
        """Encoded size of one whole group."""
        return self.ops_per_group * self.op_size + self.sequence_word_size

    def group_count(self, length: int) -> int:
        """How many whole groups fit in ``length`` bytes."""
        return length // self.group_size

    def holds_whole_groups(self, length: int) -> bool:
        """Whether ``length`` bytes divide exactly into groups."""
        return length % self.group_size == 0


#: Three 64-bit micro-ops and a 32-bit sequence word: the K8/K10-era triad.
_TRIAD = OpGroupGeometry(op_size=8, ops_per_group=3, sequence_word_size=4)

#: Four 64-bit micro-ops and a 32-bit sequence word: the Zen-era quad.
_QUAD = OpGroupGeometry(op_size=8, ops_per_group=4, sequence_word_size=4)

#: The group geometry each family uses.
_BY_FAMILY: dict[int, OpGroupGeometry] = {
    0x0F: _TRIAD,
    0x10: _TRIAD,
    0x11: _TRIAD,
    0x12: _TRIAD,
    0x17: _QUAD,
    0x19: _QUAD,
}
