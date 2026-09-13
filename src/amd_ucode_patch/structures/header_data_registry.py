#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Which header-data model a patch's family selects.
"""

from __future__ import annotations

from amd_ucode_patch.structures.header_data import HeaderData
from amd_ucode_patch.structures.header_data_default import HeaderDataDefault
from amd_ucode_patch.structures.header_data_fam0fto12 import HeaderDataFam0fto12
from amd_ucode_patch.structures.patch_level import PatchLevel

#: Families with a header-data model of their own. Families 0x0f-0x12 (K8, K10,
#: Griffin, Llano) share the triad format; Bobcat (0x14) and Bulldozer (0x15)
#: are newer but do not, and fall through to the default.
_BY_FAMILY: dict[int, type[HeaderData]] = {
    0x0F: HeaderDataFam0fto12,
    0x10: HeaderDataFam0fto12,
    0x11: HeaderDataFam0fto12,
    0x12: HeaderDataFam0fto12,
}


def is_modelled(patch_level: PatchLevel) -> bool:
    """Whether this patch's family has a header-data model of its own."""
    return patch_level.family in _BY_FAMILY


def header_data_class(patch_level: PatchLevel) -> type[HeaderData]:
    """
    The header-data class for a patch, from its family, or the default model
    when the family has none of its own.
    """
    return _BY_FAMILY.get(patch_level.family, HeaderDataDefault)


def header_data_from_bytes(patch_level: PatchLevel, data: bytes) -> HeaderData:
    """
    Parse the header-data section for a patch from its family and raw bytes.
    """
    return header_data_class(patch_level).from_bytes(data)
