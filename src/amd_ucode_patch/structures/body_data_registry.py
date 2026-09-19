#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Which body-data class a body's ``encrypted`` flag selects.
"""

from __future__ import annotations

from amd_ucode_patch.structures.body_data import BodyData
from amd_ucode_patch.structures.body_data_encrypted import EncryptedBodyData
from amd_ucode_patch.structures.body_data_plaintext import PlaintextBodyData


def body_data_class(encrypted: bool) -> type[BodyData]:
    """The body-data class for an ``encrypted`` (or not) body."""
    return EncryptedBodyData if encrypted else PlaintextBodyData


def body_data_from_bytes(encrypted: bool, data: bytes) -> BodyData:
    """Parse the body data from its raw bytes, opaque when ``encrypted``."""
    return body_data_class(encrypted)(bytes(data))
