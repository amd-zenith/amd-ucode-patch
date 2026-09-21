#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Header data for Zen 3 (0x19) and Zen 5 (0x1a).

Same 22-byte layout as the default model, except that these families put two
fields in the span their predecessors leave zero: the patch's own size, and the
patch level it expects to supersede.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_cpuid import AmdCpuId

from amd_ucode_patch.structures.header_data import HeaderData
from amd_ucode_patch.structures.patch_level import PatchLevel


@dataclass
class HeaderDataFam19to1a(HeaderData):
    """
    The 22-byte header-data region of a Zen 3 (0x19) or Zen 5 (0x1a) patch.
    """

    #: Struct layout
    _FMT: ClassVar[str] = "<HI8sH6s"
    #: Unit the patch size is counted in, in bytes.
    SIZE_UNIT: ClassVar[int] = 16

    #: The patch's total size, in :data:`SIZE_UNIT`-byte units, or ``None``
    #: where the patch does not declare one.
    #: Offset 10, 2 bytes.
    patch_size_units: int | None
    #: The patch level this patch expects to supersede, or ``None`` where the
    #: patch does not declare one. Always names the same processor as the
    #: patch's own level, and is always lower than it.
    #: Offset 12, 4 bytes.
    required_patch_level: PatchLevel | None
    #: Not modelled, kept verbatim.
    #: Offset 16, 8 bytes.
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
    def from_bytes(cls, data: bytes) -> "HeaderDataFam19to1a":
        """Parse the header data from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for family-0x19/0x1a header data: "
                f"got {len(data)}, need {cls.SIZE}"
            )
        (units, required, unknown0,
         cpuid, unknown1) = struct.unpack_from(cls._FMT, data, 0)
        return cls(
            patch_size_units=units or None,
            required_patch_level=PatchLevel(value=required) if required else None,
            unknown0=unknown0,
            cpuid=AmdCpuId.from_ucode_signature(cpuid),
            unknown1=unknown1,
        )

    @property
    def patch_size(self) -> int | None:
        """
        The patch's total size in bytes, as the header declares it, or ``None``
        where it declares none.
        """
        if self.patch_size_units is None:
            return None
        return self.patch_size_units * self.SIZE_UNIT

    def to_bytes(self) -> bytes:
        """Serialize the header data back to its exact byte encoding."""
        return struct.pack(
            self._FMT,
            self.patch_size_units or 0,
            0 if self.required_patch_level is None
            else self.required_patch_level.value,
            self.unknown0,
            self.cpuid.ucode_signature,
            self.unknown1,
        )
