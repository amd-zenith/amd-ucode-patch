#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Which signature-slot block a patch's family carries.
"""

from __future__ import annotations

from amd_ucode_patch.structures.signature import Signature
from amd_ucode_patch.structures.signature_fam16 import SignatureFam16
from amd_ucode_patch.structures.signature_fam17plus import SignatureFam17Plus

#: Families with a signature slot, and the block that occupies it.
_BY_FAMILY: dict[int, type[Signature]] = {
    0x16: SignatureFam16,
    0x17: SignatureFam17Plus,
    0x19: SignatureFam17Plus,
    0x1A: SignatureFam17Plus,
}


def signature_class(family: int) -> type[Signature] | None:
    """The signature class for ``family``, or ``None`` when it has no slot."""
    return _BY_FAMILY.get(family)


def signature_from_bytes(family: int, data: bytes) -> Signature | None:
    """
    Parse the signature block for ``family`` from its raw bytes.
    Returns ``None`` if the family has no signature slot.
    """
    cls = signature_class(family)
    if cls is None:
        return None
    return cls.from_bytes(data)
