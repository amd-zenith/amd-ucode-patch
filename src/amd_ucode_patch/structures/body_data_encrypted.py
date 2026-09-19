#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Encrypted body data: opaque, kept verbatim as raw bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

from amd_ucode_patch.structures.body_data import BodyData


@dataclass
class EncryptedBodyData(BodyData):
    """Encrypted body contents: opaque, only ever raw bytes."""

    is_encrypted = True

    #: The encrypted contents, opaque.
    data: bytes

    def to_bytes(self) -> bytes:
        """Serialize the body data back to its exact byte encoding."""
        return self.data
