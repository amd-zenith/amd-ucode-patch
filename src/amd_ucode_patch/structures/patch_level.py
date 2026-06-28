#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar


#: Effective family at which the v2 (Zen) layout applies. The Linux kernel
#: switches behaviour on ``x86_family(bsp_cpuid_1_eax) >= 0x17``.
V2_MIN_FAMILY = 0x17


class PatchLevelError(Exception):
    """Base error for patch level operations."""


class PatchLevelMismatchError(PatchLevelError):
    """Raised when comparing two v2 patch levels that target different CPUs."""


class PatchLevelVersion(IntEnum):
    """Which structural layout a :class:`PatchLevel` uses (see module docs)."""

    V1 = 1
    V2 = 2

    def __str__(self) -> str:
        return {
            PatchLevelVersion.V1: "v1 (pre-Zen)",
            PatchLevelVersion.V2: "v2 (Zen+)",
        }[self]


@dataclass
class PatchLevel(ABC):
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

    #: Layout this instance uses; set by each concrete subclass.
    version: ClassVar[PatchLevelVersion]

    value: int

    @staticmethod
    def from_bytes(buf: bytes, family: int | None = None) -> "PatchLevel":
        """
        Parse a patch level from the first 4 bytes of ``buf``.

        ``family`` is the effective CPU family (from the header's cpuid). It
        selects the layout: ``family >= 0x17`` -> v2, otherwise v1. When it is
        unknown (``None``) the value defaults to the v1 (opaque counter) layout.
        """
        if len(buf) < PatchLevel.SIZE:
            raise ValueError("not enough bytes for AMD patch level")
        (value,) = struct.unpack(PatchLevel.FMT, buf[0:PatchLevel.SIZE])
        return PatchLevel.from_value(value, family)

    @staticmethod
    def from_value(value: int, family: int | None = None) -> "PatchLevel":
        """Build the variant appropriate for ``family`` (see :meth:`from_bytes`)."""
        if family is not None and family >= V2_MIN_FAMILY:
            return PatchLevelV2(value)
        return PatchLevelV1(value)

    def to_bytes(self) -> bytes:
        return struct.pack(PatchLevel.FMT, self.value)

    @abstractmethod
    def is_valid(self, cpuid=None) -> bool:
        """
        Whether the structured fields are self-consistent (and, if ``cpuid`` is
        given, consistent with it). See the concrete variants for the rules.
        """

    @abstractmethod
    def _cmp_same(self, other: "PatchLevel") -> int:
        """Compare against a same-version instance; return -1, 0 or 1."""

    def _compare(self, other: object):
        if not isinstance(other, PatchLevel):
            return NotImplemented
        if type(self) is not type(other):
            raise PatchLevelError(
                f"cannot compare {self.version} with {other.version} patch levels"
            )
        return self._cmp_same(other)

    def __lt__(self, other: object):
        r = self._compare(other)
        return r < 0 if r is not NotImplemented else NotImplemented

    def __le__(self, other: object):
        r = self._compare(other)
        return r <= 0 if r is not NotImplemented else NotImplemented

    def __gt__(self, other: object):
        r = self._compare(other)
        return r > 0 if r is not NotImplemented else NotImplemented

    def __ge__(self, other: object):
        r = self._compare(other)
        return r >= 0 if r is not NotImplemented else NotImplemented

    def __int__(self) -> int:
        return self.value

    def __str__(self) -> str:
        return f"{self.value:08x}"


@dataclass
class PatchLevelV1(PatchLevel):
    """
    Pre-Zen (family <= 0x16) patch level
    An opaque, monotonically increasing counter.
    """

    version: ClassVar[PatchLevelVersion] = PatchLevelVersion.V1

    @property
    def rev(self) -> int:
        """The monotonic patch counter."""
        return self.value

    def is_valid(self, cpuid=None) -> bool:
        # v1 has no documented internal structure to validate. The top byte
        # only advisorily tracks the extended family and a few genuine early
        # patches violate even that, so validity is not gated on it.
        return True

    def _cmp_same(self, other: "PatchLevel") -> int:
        return (self.value > other.value) - (self.value < other.value)


@dataclass
class PatchLevelV2(PatchLevel):
    """
    Zen and later (family >= 0x17) patch level.
    The whole word decodes (Linux ``union zen_patch_rev``); the upper three bytes
    identify the target CPU and only :attr:`rev` (low byte) increments between
    updates.

    Comparison requires the same target CPU: comparing two v2 patch levels whose
    upper three bytes differ raises :class:`PatchLevelMismatchError`; otherwise
    the low :attr:`rev` byte is compared.
    """

    version: ClassVar[PatchLevelVersion] = PatchLevelVersion.V2

    @property
    def rev(self) -> int:
        """Patch sequence number (bits 7:0); the only part that increments."""
        return self.value & 0xFF

    @property
    def stepping(self) -> int:
        """CPU stepping (bits 11:8)."""
        return (self.value >> 8) & 0xF

    @property
    def modelbase(self) -> int:
        """Model low nibble (bits 15:12)."""
        return (self.value >> 12) & 0xF

    @property
    def reserved(self) -> int:
        """Reserved field (bits 19:16); expected to be 0."""
        return (self.value >> 16) & 0xF

    @property
    def modelext(self) -> int:
        """Model high nibble (bits 23:20)."""
        return (self.value >> 20) & 0xF

    @property
    def familyext(self) -> int:
        """Extended family (bits 31:24); ``family == 0xF + familyext``."""
        return (self.value >> 24) & 0xFF

    @property
    def family(self) -> int:
        """Effective family (``0xF + familyext``)."""
        return 0xF + self.familyext

    @property
    def model(self) -> int:
        """Effective model (``(modelext << 4) | modelbase``)."""
        return (self.modelext << 4) | self.modelbase

    def matches(self, cpuid) -> bool:
        """Whether the embedded f/m/s match an ``AmdCpuId`` (upper 3 bytes)."""
        expected = (
            (cpuid.familyext << 16)
            | (cpuid.modelext << 12)
            | (cpuid.modelbase << 4)
            | cpuid.stepping
        )
        return (self.value >> 8) == expected

    def is_valid(self, cpuid=None) -> bool:
        if self.reserved != 0:
            return False
        if self.familyext < (V2_MIN_FAMILY - 0xF):
            return False
        if cpuid is not None and not self.matches(cpuid):
            return False
        return True

    def _cmp_same(self, other: "PatchLevel") -> int:
        if (self.value >> 8) != (other.value >> 8):
            raise PatchLevelMismatchError(f"patch levels target different CPUs: {self} vs {other}")
        return (self.rev > other.rev) - (self.rev < other.rev)
