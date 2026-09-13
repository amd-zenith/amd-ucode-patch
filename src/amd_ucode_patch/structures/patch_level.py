#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The patch level
The second 32-bit word of the patch header (offset 4).

Known elsewhere as Linux ``patch_id``, zentool ``revision``, and "patch level" /
"ucode level". It is the value the CPU reports via ``rdmsr 0x8B``
(``MSR_AMD64_PATCH_LEVEL``) for the loaded microcode, and what the loader uses to
decide whether an update is newer than the running patch.
"""

from __future__ import annotations

import struct
import warnings
from dataclasses import dataclass
from typing import ClassVar

from amd_cpuid import AmdCpuId

#: Families AMD has actually shipped (base ``0xF`` plus extended family). Used
#: to flag a decoded family that is not real silicon.
_KNOWN_FAMILIES: frozenset[int] = frozenset(
    {0x0F, 0x10, 0x11, 0x12, 0x14, 0x15, 0x16, 0x17, 0x19, 0x1A}
)

#: Families whose patch level packs the full CPUID beside the revision counter.
_CPUID_FAMILIES: frozenset[int] = frozenset({0x16, 0x17, 0x19, 0x1A})

#: Patch-level words whose family byte does not match the part they belong to,
#: mapped to the real *extended* family verified from the corpus (filename,
#: CPUID field and loader id all agree they are family 0x0F K8 patches, i.e.
#: extended family 0x00). Correcting the extended family here fixes ``family``
#: too, since it is derived from it. Both are one-off K8 oddities.
_ANOMALIES: dict[int, int] = {
    0x02000008: 0x00,   # top byte 0x02 would read as family 0x11
    0xC0012102: 0x00,   # top byte 0xC0 would read as family 0xCF (not real)
}


@dataclass
class PatchLevel:
    """The 4-byte patch level, as an editable little-endian u32 value."""

    #: Size of the patch-level word.
    SIZE: ClassVar[int] = 4
    #: Struct layout: little-endian u32.
    _FMT: ClassVar[str] = "<I"

    value: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "PatchLevel":
        """Parse a patch level from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for AMD patch level: got {len(data)}, need {cls.SIZE}"
            )
        (value,) = struct.unpack_from(cls._FMT, data, 0)
        return cls(value=value)

    def to_bytes(self) -> bytes:
        """Serialize the patch level back to its exact byte encoding."""
        return struct.pack(self._FMT, self.value)

    @property
    def is_anomalous(self) -> bool:
        """
        Whether this is one of the known-malformed patch levels whose top byte
        does not name its real family (see :data:`_ANOMALIES`), and whose
        extended family is therefore corrected on read.
        """
        return self.value in _ANOMALIES

    @property
    def extended_family(self) -> int:
        """
        The extended family: the top byte (bits 31-24). This is the one field
        the patch level carries in every version -- the rest of the word is a
        version-dependent counter (pre-Zen) or a packed CPUID (Zen).

        Two known K8 patches carry a top byte that does not match their part;
        for those this returns the value verified from the corpus and warns.
        Correcting it here also fixes :attr:`family`, which derives from it.
        """
        corrected = _ANOMALIES.get(self.value)
        if corrected is not None:
            raw = (self.value >> 24) & 0xFF
            warnings.warn(
                f"Patch level {self.value:#010x}: top byte {raw:#04x} is "
                f"malformed; using the extended family {corrected:#04x} "
                f"verified for this patch",
                stacklevel=2,
            )
            return corrected
        return (self.value >> 24) & 0xFF

    @property
    def family(self) -> int:
        """
        The CPU family: base family ``0xF`` plus :attr:`extended_family`. So
        ``0x08`` in the top byte is family ``0x17`` (Zen 1).

        Inherits the correction and warning from :attr:`extended_family`. A
        family that is not real AMD silicon warns too, but is returned as
        decoded since there is nothing to correct it to.
        """
        family = 0xF + self.extended_family
        if family not in _KNOWN_FAMILIES:
            warnings.warn(
                f"Patch level {self.value:#010x}: decoded family "
                f"{family:#04x} is not a known AMD family",
                stacklevel=2,
            )
        return family

    @property
    def cpuid(self) -> AmdCpuId | None:
        """
        The CPUID this patch targets, recovered from the model and stepping the
        patch level packs beside the family. Only on Jaguar (0x16) and Zen (0x17+).
        """
        if self.family not in _CPUID_FAMILIES:
            return None
        byte2 = (self.value >> 16) & 0xFF
        byte1 = (self.value >> 8) & 0xFF
        model_ext = byte2 & 0xF if self.family == 0x16 else byte2 >> 4
        signature = (self.extended_family << 12) | (model_ext << 8) | byte1
        return AmdCpuId.from_ucode_signature(signature)

    def __int__(self) -> int:
        return self.value

    def __str__(self) -> str:
        return f"{self.value:08x}"
