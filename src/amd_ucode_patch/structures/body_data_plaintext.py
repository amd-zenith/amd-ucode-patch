#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Non-encrypted body data.
"""

from __future__ import annotations

from dataclasses import dataclass

from amd_ucode_patch.structures.body_data import BodyData
from amd_ucode_patch.structures.match_registers import MatchRegisters


@dataclass
class PlaintextBodyData(BodyData):
    """
    Non-encrypted body contents: the match registers a format opens its body
    with, then the rest kept verbatim and not yet modelled.
    """

    is_encrypted = False

    #: The match registers the body opens with. ``None`` on a format whose body
    #: does not begin with them.
    #: Offset 0, :attr:`MatchRegisters.size` bytes.
    match_registers: MatchRegisters | None
    #: The contents past the match registers, kept verbatim and not yet
    #: modelled.
    unknown0: bytes

    @classmethod
    def from_bytes(cls, data: bytes, family: int) -> "PlaintextBodyData":
        """
        Parse the plaintext body data from ``data`` for the given CPU ``family``.

        A body too short to hold the match registers its family declares is
        malformed and is refused, as every other section does with a buffer it
        cannot fill.
        """
        data = bytes(data)
        registers = MatchRegisters.for_family(data, family)
        data_offset = 0 if registers is None else registers.size
        return cls(match_registers=registers, unknown0=data[data_offset:])

    def to_bytes(self) -> bytes:
        """Serialize the body data back to its exact byte encoding."""
        head = b"" if self.match_registers is None else self.match_registers.to_bytes()
        return head + self.unknown0
