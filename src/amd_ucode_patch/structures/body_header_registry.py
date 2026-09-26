#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Which body-header model a patch's family carries.
"""

from __future__ import annotations

from amd_ucode_patch.structures.body_header import BodyHeader
from amd_ucode_patch.structures.body_header_fam16to19 import BodyHeaderFam16to19
from amd_ucode_patch.structures.body_header_fam1a import BodyHeaderFam1a

#: Families whose body begins with a body header: Jaguar (0x16) and the Zen
#: parts (0x17+). These are exactly the families with a signature slot. They
#: share one layout, except Zen 5 (0x1a) fills the offset-2 span its
#: predecessors leave zero with a copy of the loader id.
_BY_FAMILY: dict[int, type[BodyHeader]] = {
    0x16: BodyHeaderFam16to19,
    0x17: BodyHeaderFam16to19,
    0x19: BodyHeaderFam16to19,
    0x1A: BodyHeaderFam1a,
}


def body_header_class(family: int) -> type[BodyHeader] | None:
    """The body-header class for ``family``, or ``None`` when it has none."""
    return _BY_FAMILY.get(family)


def body_header_from_bytes(family: int, data: bytes) -> BodyHeader | None:
    """
    Parse the body header for ``family`` from the start of ``data``, or return
    ``None`` when the family carries no body header (or ``data`` is too short
    for one).
    """
    cls = body_header_class(family)
    if cls is None or len(data) < BodyHeader.SIZE:
        return None
    return cls.from_bytes(data)
