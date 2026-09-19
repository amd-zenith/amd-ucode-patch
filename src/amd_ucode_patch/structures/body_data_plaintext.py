#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Non-encrypted body data.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.body_data import BodyData


@dataclass
class PlaintextBodyData(BodyData):
    """
    Non-encrypted body contents: the match registers a format opens its body
    with, then the rest kept verbatim and not yet modelled.
    """

    is_encrypted = False

    #: The number of match registers each family opens its body with.
    _MATCH_REGISTERS_COUNT: ClassVar[dict[int, int]] = {
        0x0F: 8,
        0x10: 8,
        0x11: 8,
    }

    #: The match registers the body opens with, as raw u32s. ``None`` on a
    #: format whose body does not begin with them.
    #: Offset 0, ``4 * len(match_registers)`` bytes.
    #: Other names:
    #:   - Linux kernel: ``match_reg[8]``
    match_registers: list[int] | None
    #: The contents past the match registers, kept verbatim and not yet
    #: modelled.
    unknown0: bytes

    @classmethod
    def match_register_count(cls, family: int) -> int:
        """How many match registers ``family`` opens its body with, 0 if unknown."""
        return cls._MATCH_REGISTERS_COUNT.get(family, 0)

    @classmethod
    def from_bytes(cls, data: bytes, family: int) -> "PlaintextBodyData":
        """
        Parse the plaintext body data from ``data`` for the given CPU ``family``.

        A body too short to hold the match registers its family declares is
        malformed and is refused, as every other section does with a buffer it
        cannot fill.
        """
        data = bytes(data)
        match_count = cls.match_register_count(family)
        if match_count <= 0:
            return cls(match_registers=None, unknown0=data)
        data_offset = match_count * 4
        if len(data) < data_offset:
            raise ValueError(
                f"not enough bytes for the family {family:#04x} match "
                f"registers: got {len(data)}, need {data_offset}"
            )
        return cls(
            match_registers=list(struct.unpack_from(f"<{match_count}I", data, 0)),
            unknown0=data[data_offset:],
        )

    def to_bytes(self) -> bytes:
        """Serialize the body data back to its exact byte encoding."""
        return (
            (struct.pack(f"<{len(self.match_registers)}I", *self.match_registers)
             if self.match_registers else b"")
            + self.unknown0
        )
