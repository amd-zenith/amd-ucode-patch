#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from dataclasses import dataclass
from amd_cpuid import AmdCpuId
from amd_ucode_patch.structures.patch_date import PatchDate
from amd_ucode_patch.structures.patch_level import PatchLevel
from amd_ucode_patch.structures.signature import Signature


#: Patches are cryptographically signed starting with Zen (family 0x17). Earlier
#: families carry no signature block.
SIGNED_MIN_FAMILY = 0x17


@dataclass
class PatchHeader:
    '''
    AMD microcode patch header.

    The fixed 32-byte core is the Linux ``microcode_header_amd``. The fields the
    project interprets are:

    - ``date``        -- Build date in BCD format
    - ``patch_level`` -- Patch ID / revision, the value ``rdmsr 0x8B`` reports
    - ``loader_id``   -- loader / patch-format id the microcode loader checks for compatibility
    - ``cpuid``       -- Target processor ID

    On Zen and later (family >= 0x17) a 768-byte cryptographic ``Signature`` block.

    The header has two sizes: ``SIZE`` is the fixed core (32 bytes) and the
    ``size`` property is the total encoding (core + signature block when present).
    '''
    # Fields after the leading PatchDate (data_code) and PatchLevel (patch_id).
    FMT = "<HBB I II H BBBBBB"
    # Size of the fixed core struct (the Linux ``microcode_header_amd``). The
    # optional Zen signature block follows it; use ``size`` for the total.
    SIZE = PatchDate.SIZE + PatchLevel.SIZE + struct.calcsize(FMT)

    #: Build date (offset 0, u32), little-endian packed BCD ``0xMMDDYYYY`` (year in
    #: the low 16 bits). Known elsewhere as ``data_code`` (Linux
    #: ``microcode_header_amd``) and the "date code" (AMD patent US6438664). An
    #: informational stamp of when the patch was built; the loader does not use it
    #: to match or order patches. Modeled by :class:`PatchDate`.
    date: PatchDate
    #: Patch level / update revision (offset 4, u32). Known elsewhere as
    #: ``patch_id`` (Linux), ``revision`` (zentool) and "patch ID" (US6438664); it
    #: is the value the CPU reports via ``rdmsr 0x8B`` (``MSR_AMD64_PATCH_LEVEL``)
    #: for the loaded microcode. The loader uses it to decide whether an update is
    #: newer than the running patch; on Zen the upper three bytes also encode the
    #: target family/model/stepping. Modeled by :class:`PatchLevel`.
    patch_level: PatchLevel
    #: Loader ID / patch-format ID (offset 8, u16). Known elsewhere as
    #: ``mc_patch_data_id`` (Linux ``microcode_header_amd``), ``format`` (zentool
    #: ``struct ucodehdr``) and the "microcode patch block (MPB) ID" (AMD patent
    #: US6438664). Its purpose is a format-compatibility check: the on-chip
    #: microcode loader compares this id against the id it supports and rejects
    #: the update (GP fault, per US6438664) on a mismatch. In effect it identifies
    #: the patch format/generation.
    loader_id: int
    unk0: int
    unk1: int
    unk2: int
    unk3: int
    unk4: int
    cpuid: AmdCpuId
    unk5: int
    unk6: int
    unk7: int
    unk8: int
    unk9: int
    unk10: int
    #: Cryptographic signature block; present only on Zen (family >= 0x17).
    signature: Signature | None

    @staticmethod
    def from_bytes(buf: bytes) -> "PatchHeader":
        if len(buf) < PatchHeader.SIZE:
            raise ValueError("not enough bytes for AMD header")
        date = PatchDate.from_bytes(buf)
        rest_start = PatchDate.SIZE + PatchLevel.SIZE
        chunk = buf[rest_start:PatchHeader.SIZE]
        vals = struct.unpack(PatchHeader.FMT, chunk)
        cpuid = AmdCpuId.from_ucode_signature(vals[6])
        # The patch level layout depends on the CPU family, so build cpuid first.
        patch_level = PatchLevel.from_bytes(buf[PatchDate.SIZE:], family=cpuid.family)
        # The signature block follows the core struct, on Zen and later only.
        signature = (
            Signature.from_bytes(buf[PatchHeader.SIZE:])
            if cpuid.family >= SIGNED_MIN_FAMILY
            else None
        )
        return PatchHeader(
            date=date,
            patch_level=patch_level,
            loader_id=vals[0],
            unk0=vals[1],
            unk1=vals[2],
            unk2=vals[3],
            unk3=vals[4],
            unk4=vals[5],
            cpuid=cpuid,
            unk5=vals[7],
            unk6=vals[8],
            unk7=vals[9],
            unk8=vals[10],
            unk9=vals[11],
            unk10=vals[12],
            signature=signature,
        )

    @property
    def size(self) -> int:
        """Total encoded size: the core struct plus the signature block if present."""
        return PatchHeader.SIZE + (Signature.SIZE if self.signature is not None else 0)

    def to_bytes(self) -> bytes:
        core = self.date.to_bytes() + self.patch_level.to_bytes() + struct.pack(
            PatchHeader.FMT,
            self.loader_id,
            self.unk0,
            self.unk1,
            self.unk2,
            self.unk3,
            self.unk4,
            self.cpuid.ucode_signature,
            self.unk5,
            self.unk6,
            self.unk7,
            self.unk8,
            self.unk9,
            self.unk10,
        )
        if self.signature is not None:
            core += self.signature.to_bytes()
        return core
