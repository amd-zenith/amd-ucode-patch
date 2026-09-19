#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Header data for a family with no format-specific model of its own.
Models only what every known format agrees on, and keeps the rest verbatim.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_cpuid import AmdCpuId

from amd_ucode_patch.structures.header_data import HeaderData


@dataclass
class HeaderDataDefault(HeaderData):
    """
    The 22-byte header-data region of a patch in an unmodelled format.
    """

    #: Struct layout
    _FMT: ClassVar[str] = "<14sH6s"

    #: Not modelled, kept verbatim.
    #: Offset 10, 14 bytes.
    unknown0: bytes
    #: Processor the patch targets, as family, model and stepping. It is the
    #: key the container's equivalence table maps a CPUID onto, so the loader
    #: matches a patch by it.
    #: Offset 24, 2 bytes.
    #: Other names:
    #:   - Linux kernel: ``processor_rev_id``
    #:   - zentool: ``cpuid`` (a u32 spanning offsets 24-27)
    cpuid: AmdCpuId
    #: Not modelled, kept verbatim.
    #: Offset 26, 6 bytes.
    unknown1: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "HeaderDataDefault":
        """Parse the header data from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for header data: got {len(data)}, "
                f"need {cls.SIZE}"
            )
        unknown0, cpuid, unknown1 = struct.unpack_from(cls._FMT, data, 0)
        return cls(
            unknown0=unknown0,
            cpuid=AmdCpuId.from_ucode_signature(cpuid),
            unknown1=unknown1,
        )

    def to_bytes(self) -> bytes:
        """Serialize the header data back to its exact byte encoding."""
        return struct.pack(
            self._FMT,
            self.unknown0,
            self.cpuid.ucode_signature,
            self.unknown1,
        )
