#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Header data for Bobcat (0x14) and Bulldozer (0x15).

Same 22-byte layout as the default model, except that one bit of the
equivalence id is not part of the CPUID and it indicates whether the
body is encrypted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_cpuid import AmdCpuId

from amd_ucode_patch.structures.header_data import HeaderData


@dataclass
class HeaderDataFam14to15(HeaderData):
    """
    The 22-byte header-data region of a Bobcat (0x14) or Bulldozer (0x15) patch.
    """

    #: Struct layout
    _FMT: ClassVar[str] = "<14sH6s"
    #: The bit of the equivalence id that is not part of the CPUID. It marks
    #: the *unencrypted* variant: AMD ships some of these patches twice under
    #: two ids, and the copy whose id has this bit set is in the clear while the
    #: one without it is encrypted.
    _UNENCRYPTED_BIT: ClassVar[int] = 1 << 11

    #: Not modelled, kept verbatim. Zero across the corpus for both families.
    #: Offset 10, 14 bytes.
    unknown0: bytes
    #: Whether the patch body is encrypted: the inverse of bit 11 of the
    #: equivalence id, which marks the unencrypted variant.
    #: Offset 24, within the 2-byte id.
    encrypted: int
    #: Processor the patch targets, as family, model and stepping, with the
    #: encrypted bit masked off. It is the key the container's equivalence table
    #: maps a CPUID onto, so the loader matches a patch by it.
    #: Offset 24, 2 bytes, shared with :attr:`encrypted`.
    #: Other names:
    #:   - Linux kernel: ``processor_rev_id``
    #:   - zentool: ``cpuid`` (a u32 spanning offsets 24-27)
    cpuid: AmdCpuId
    #: Not modelled, kept verbatim.
    #: Offset 26, 6 bytes.
    unknown1: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "HeaderDataFam14to15":
        """Parse the header data from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for family-0x14/0x15 header data: "
                f"got {len(data)}, need {cls.SIZE}"
            )
        unknown0, equivalence_id, unknown1 = struct.unpack_from(cls._FMT, data, 0)
        return cls(
            unknown0=unknown0,
            encrypted=int(not equivalence_id & cls._UNENCRYPTED_BIT),
            cpuid=AmdCpuId.from_ucode_signature(
                equivalence_id & ~cls._UNENCRYPTED_BIT
            ),
            unknown1=unknown1,
        )

    @property
    def is_encrypted(self) -> bool:
        """
        Whether the header declares the body encrypted. These families carry no
        body header, so this is the only place the signal lives -- which is why
        this format answers where the others return ``None``.
        """
        return bool(self.encrypted)

    @property
    def equivalence_id(self) -> int:
        """
        The id exactly as stored: the CPUID with the unencrypted-variant bit
        folded back in. What the container's equivalence table is keyed on, and
        what the collection's filenames carry.
        """
        return self.cpuid.ucode_signature | (
            0 if self.encrypted else self._UNENCRYPTED_BIT
        )

    def to_bytes(self) -> bytes:
        """Serialize the header data back to its exact byte encoding."""
        return struct.pack(
            self._FMT,
            self.unknown0,
            self.equivalence_id,
            self.unknown1,
        )
