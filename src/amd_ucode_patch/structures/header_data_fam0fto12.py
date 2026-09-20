#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Header data for family 0x12 and older.
Used by K8/K10/Griffin/Llano (families 0f/10/11/12), the pre-Bobcat parts whose
patch body is an array of micro-op triads.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from amd_cpuid import AmdCpuId

from amd_ucode_patch.structures.header_data import HeaderData


@dataclass
class HeaderDataFam0fto12(HeaderData):
    """
    The 22-byte header-data region of a family 0x12-or-older patch.
    Used by K8/K10/Griffin/Llano (families 0f/10/11/12).
    """

    #: Struct layout
    _FMT: ClassVar[str] = "<BBII4sH6s"

    #: Length of the patch data block, in micro-op triads. A triad is three
    #: micro-ops and a sequence control field.
    #: Offset 10, 1 byte.
    #: Other names:
    #:   - Linux kernel: ``mc_patch_data_len``
    #:   - zentool: ``patchlen``
    #:   - AMD patent US6438664B1: patch length
    op_triad_count: int
    #: Whether the loader jumps to a patch RAM location immediately after
    #: loading the patch, instead of resuming normal operation.
    #: Offset 11, 1 byte.
    #: Other names:
    #:   - Linux kernel: ``init_flag``
    #:   - zentool: ``init``
    #:   - AMD patent US6438664B1: init flag
    init_flag: int
    #: Sum of the u32 words of the micro-op triad array, verifying correct
    #: reception of the patch data.
    #: Offset 12, 4 bytes.
    #: Other names:
    #:   - Linux kernel: ``mc_patch_data_checksum``
    #:   - zentool: ``checksum``
    #:   - AMD patent US6438664B1: check sum
    op_triad_checksum: int
    #: PCI device id of the northbridge this patch is restricted to, or zero
    #: for no restriction.
    #: Offset 16, 4 bytes.
    #: Other names:
    #:   - Linux kernel: ``nb_dev_id``
    #:   - zentool: ``northbridge``
    nb_dev_id: int
    #: Not modelled, kept verbatim.
    #: Offset 20, 4 bytes.
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
    def from_bytes(cls, data: bytes) -> "HeaderDataFam0fto12":
        """Parse the header data from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for family-0x12-or-older header data: got {len(data)}, "
                f"need {cls.SIZE}"
            )
        (op_triad_count, init_flag, op_triad_checksum, nb_dev_id, unknown0,
         cpuid, unknown1) = struct.unpack_from(cls._FMT, data, 0)
        return cls(
            op_triad_count=op_triad_count,
            init_flag=init_flag,
            op_triad_checksum=op_triad_checksum,
            nb_dev_id=nb_dev_id,
            unknown0=unknown0,
            cpuid=AmdCpuId.from_ucode_signature(cpuid),
            unknown1=unknown1,
        )

    def to_bytes(self) -> bytes:
        """Serialize the header data back to its exact byte encoding."""
        return struct.pack(
            self._FMT,
            self.op_triad_count,
            self.init_flag,
            self.op_triad_checksum,
            self.nb_dev_id,
            self.unknown0,
            self.cpuid.ucode_signature,
            self.unknown1,
        )
