#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Which body-data model a patch's family and ``encrypted`` flag select.
"""

from __future__ import annotations

from amd_ucode_patch.structures.body_data import BodyData
from amd_ucode_patch.structures.body_data_encrypted import EncryptedBodyData
from amd_ucode_patch.structures.body_data_fam0fto12 import BodyDataFam0fto12
from amd_ucode_patch.structures.body_data_fam14to15 import BodyDataFam14to15
from amd_ucode_patch.structures.body_data_fam17plus import BodyDataFam17Plus
from amd_ucode_patch.structures.body_data_plaintext import PlaintextBodyData

#: Families whose body has a model of its own. Families 0x0f-0x12 (K8, K10,
#: Griffin, Llano) open their body with the match registers, as do the Zen
#: families (0x17, 0x19, 0x1a); Bobcat (0x14) and Bulldozer (0x15) open theirs
#: with a frame. Any other family falls through to the unmodelled plaintext
#: body.
_BY_FAMILY: dict[int, type[BodyData]] = {
    0x0F: BodyDataFam0fto12,
    0x10: BodyDataFam0fto12,
    0x11: BodyDataFam0fto12,
    0x12: BodyDataFam0fto12,
    0x14: BodyDataFam14to15,
    0x15: BodyDataFam14to15,
    0x17: BodyDataFam17Plus,
    0x19: BodyDataFam17Plus,
    0x1A: BodyDataFam17Plus,
}


def is_modelled(family: int) -> bool:
    """Whether this family's body has a model of its own."""
    return family in _BY_FAMILY


def body_data_from_bytes(family: int, encrypted: bool, data: bytes) -> BodyData:
    """
    Parse the body data from its raw bytes, opaque when ``encrypted``.

    An encrypted body is opaque whatever its family. A plaintext one gets its
    family's model, or the unmodelled plaintext body when the family has none.
    """
    if encrypted:
        return EncryptedBodyData(bytes(data))
    model = _BY_FAMILY.get(family)
    if model is None:
        return PlaintextBodyData(bytes(data))
    return model.from_bytes(data, family)
