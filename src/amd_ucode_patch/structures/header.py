#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The patch header: everything in a patch that is not the (signed) body.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.date import Date
from amd_ucode_patch.structures.header_data import HeaderData
from amd_ucode_patch.structures.header_data_registry import header_data_from_bytes
from amd_ucode_patch.structures.loader_id import LoaderId
from amd_ucode_patch.structures.patch_level import PatchLevel
from amd_ucode_patch.structures.signature import Signature
from amd_ucode_patch.structures.signature_registry import signature_from_bytes


@dataclass
class Header:
    """
    The microcode patch header.
    Consists of a fixed set of initial fields: Date, patch level, loader ID.
    After the fixed set of fields, a version dependent data section follows.
    Finally, if present, a signature block follows the core and data section.
    """

    #: Size of the fixed core struct. The total encoded size (core + signature
    #: block when present) is the :attr:`size` property.
    CORE_SIZE: ClassVar[int] = 32
    #: Offset of the build date (a :class:`Date`) at the start of the core.
    _DATE_OFF: ClassVar[int] = 0
    #: Offset of the patch level (a :class:`PatchLevel`).
    _PATCH_LEVEL_OFF: ClassVar[int] = 4
    #: Offset of the loader id (a :class:`LoaderId`).
    _LOADER_ID_OFF: ClassVar[int] = 8
    #: Offset of the grouped :class:`HeaderData` (the rest of the core).
    _DATA_OFF: ClassVar[int] = 10

    #: Build date (offset 0), a packed-BCD :class:`Date`.
    date: Date
    #: Patch level / update revision (offset 4), a :class:`PatchLevel`.
    patch_level: PatchLevel
    #: Loader id (offset 8), a :class:`LoaderId`. Kept as a stored value; the
    #: parser dispatches on the CPU family (from the patch level), not on this.
    loader_id: LoaderId
    #: The rest of the fixed core (offsets 10-32), grouped as :class:`HeaderData`.
    #: Which concrete model this is depends on :attr:`loader_id`.
    data: HeaderData
    #: Signature block after the core; present only on signed (Zen) patches.
    signature: Signature | None

    @classmethod
    def from_bytes(cls, data: bytes) -> "Header":
        """
        Parse the header from ``data``.

        The header data and the signature block are both selected by the CPU
        family from :attr:`patch_level`. A family with no signature slot gets
        ``None``.
        """
        if len(data) < cls.CORE_SIZE:
            raise ValueError(
                f"not enough bytes for AMD header: got {len(data)}, need {cls.CORE_SIZE}"
            )
        date = Date.from_bytes(data[cls._DATE_OFF:])
        patch_level = PatchLevel.from_bytes(data[cls._PATCH_LEVEL_OFF:])
        loader_id = LoaderId.from_bytes(data[cls._LOADER_ID_OFF:])
        header_data = header_data_from_bytes(patch_level, data[cls._DATA_OFF:])
        signature = signature_from_bytes(patch_level.family, data[cls.CORE_SIZE:])
        return cls(
            date=date,
            patch_level=patch_level,
            loader_id=loader_id,
            data=header_data,
            signature=signature,
        )

    @property
    def size(self) -> int:
        """Total encoded size: the core, plus the signature block if present."""
        return self.CORE_SIZE + (self.signature.SIZE if self.signature is not None else 0)

    def to_bytes(self) -> bytes:
        """Serialize the header back to its exact byte encoding."""
        core = (
            self.date.to_bytes()
            + self.patch_level.to_bytes()
            + self.loader_id.to_bytes()
            + self.data.to_bytes()
        )
        if self.signature is not None:
            core += self.signature.to_bytes()
        return core
