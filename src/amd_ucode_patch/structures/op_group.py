#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
A micro-op group: a fixed number of u64 micro-ops and a u32 sequence word.

The reusable unit of decoded microcode. A pre-Zen *triad* is a group of 3 ops
(28 bytes); a Zen *quad* is 4 ops (36 bytes). ``size = op_count * 8 + 4``.

This is a decoded view for direct micro-op access. The Zen families store their
quads in the clear, so :meth:`from_bytes` reads them straight off the little-
endian body. The pre-Zen families ship their triads scrambled; those come
through :mod:`amd_ucode_patch.structures.triad_obfuscation` first, which yields
the ops and sequence word this class holds.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class OpGroup:
    """``ops`` micro-ops (u64 each) followed by a u32 sequence word."""

    #: The micro-ops, in order.
    #: Other names:
    #:   - zentool: ``uopquad_t`` (Zen)
    #:   - USENIX'17 / RUB: the triad's operations (pre-Zen)
    ops: list[int]
    #: The sequence control word that ends the group: where execution goes next.
    #: Other names:
    #:   - zentool: ``seqword_t``
    #:   - RUB: ``sw``
    control: int

    @staticmethod
    def size(op_count: int) -> int:
        """Encoded size of a group with ``op_count`` micro-ops, in bytes."""
        return op_count * 8 + 4

    @classmethod
    def from_bytes(cls, data: bytes, op_count: int) -> "OpGroup":
        """
        Parse one group of ``op_count`` little-endian u64 micro-ops and its u32
        sequence word from the start of ``data``. Suitable for the Zen quads,
        which are stored in the clear; the scrambled pre-Zen triads must be run
        through :func:`~amd_ucode_patch.structures.triad_obfuscation.deobfuscate_triad`
        instead.
        """
        ops = list(struct.unpack_from(f"<{op_count}Q", data, 0))
        (control,) = struct.unpack_from("<I", data, op_count * 8)
        return cls(ops=ops, control=control)

    @classmethod
    def array_from_bytes(cls, data: bytes, op_count: int) -> list["OpGroup"]:
        """Parse ``data`` as a whole number of ``op_count``-op groups."""
        step = cls.size(op_count)
        return [cls.from_bytes(data[i:i + step], op_count)
                for i in range(0, len(data) - step + 1, step)]

    def to_bytes(self) -> bytes:
        """
        Serialize the group to its little-endian byte encoding. This is the
        on-disk form for the Zen quads; a pre-Zen triad's on-disk bytes are
        scrambled and come from
        :func:`~amd_ucode_patch.structures.triad_obfuscation.obfuscate_triad`.
        """
        return (struct.pack(f"<{len(self.ops)}Q", *self.ops)
                + struct.pack("<I", self.control))
