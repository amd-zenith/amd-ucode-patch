#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from dataclasses import dataclass


@dataclass
class PatchLevel:
    """
    Microcode patch level (a.k.a. patch ID / update revision), the second 32-bit
    word of an AMD microcode patch header.

    Names across sources, all the same ``u32`` at header offset 4:

    - ``patch_id``           -- Linux ``struct microcode_header_amd``
    - ``revision``           -- zentool ``struct ucodehdr``
    - ``ucode_level`` / "Patch level" -- AMD ``amd_ucode_info.py`` / linux-firmware
    - ``MSR_AMD64_PATCH_LEVEL`` (MSR ``0x8B``) -- what the CPU reports for the
      currently loaded patch; the kernel verifies ``rdmsr 0x8B == hdr.patch_id``
      after applying a patch.

    The value is compared as a whole word by the loader, but it is not opaque.
    It is a structured patch identifier whose layout depends on the CPU
    generation. There are two documented versions ("v1" pre-Zen, "v2" Zen).

    --------------------------------------------------------------------------
    Version 1 -- pre-Zen (family <= 0x16)
    --------------------------------------------------------------------------
    The patch level is an *opaque, monotonically increasing counter*. The CPU
    that a patch targets is NOT encoded here; matching is done via a separate
    equivalence table (``equiv_cpu_entry``) keyed on ``CPUID(1).EAX``, and the
    header's ``processor_rev_id`` links each patch to that table.

    Apply rule (kernel): whole-word compare -- ``n->patch_id > p->patch_id``.

    No source documents an internal sub-byte layout for v1. Empirically over the
    collection the top byte still tracks the extended family
    (``patch_id[31:24] == cpuid.familyext``), but the low 24 bits are just a
    counter and bits ``[19:16]`` are NOT reserved (some v1 patches set them).
    Do not decode model/stepping from a v1 patch level.

    --------------------------------------------------------------------------
    Version 2 -- Zen and later (family >= 0x17)
    --------------------------------------------------------------------------
    The patch level hardcodes the target family/model/stepping so the loader can
    skip the equivalence table entirely. Bit layout (Linux ``union
    zen_patch_rev``)::

        bits [ 7: 0]  rev         patch sequence number (the only part that
                                  increments between updates for a given CPU)
        bits [11: 8]  stepping    CPU stepping
        bits [15:12]  model       model, low nibble
        bits [19:16]  (reserved)  always 0
        bits [23:20]  ext_model   model, high nibble
        bits [31:24]  ext_fam     extended family (effective family - 0xF)

    Effective family = ``0xF + ext_fam``; effective model =
    ``(ext_model << 4) | model``. These upper three bytes mirror
    ``CPUID(1).EAX`` (base family nibble is forced to ``0xF`` and reconstructed).

    Apply rule (kernel ``patch_newer``): the stepping must match, then compare
    only the low byte -- ``zn.rev > zp.rev``.

    --------------------------------------------------------------------------
    References
    --------------------------------------------------------------------------
    - Linux ``arch/x86/kernel/cpu/microcode/amd.c`` -- ``struct
      microcode_header_amd``, ``union zen_patch_rev``, ``patch_newer()``,
      ``equiv_cpu_entry``, ``MSR_AMD64_PATCH_LEVEL``.
    - AMD ``amd_ucode_info.py`` (AMDESE) and linux-firmware ``amd-ucode/README``.
    - AMD CPUID Specification (PDF 25481) for the ``CPUID(1).EAX`` f/m/s layout.
    """

    FMT = "<I"
    SIZE = struct.calcsize(FMT)

    value: int

    @staticmethod
    def from_bytes(buf: bytes) -> "PatchLevel":
        if len(buf) < PatchLevel.SIZE:
            raise ValueError("not enough bytes for AMD patch level")
        (value,) = struct.unpack(PatchLevel.FMT, buf[0:PatchLevel.SIZE])
        return PatchLevel(value=value)

    def to_bytes(self) -> bytes:
        return struct.pack(PatchLevel.FMT, self.value)

    def __int__(self) -> int:
        return self.value

    def __str__(self) -> str:
        return f"{self.value:08x}"
