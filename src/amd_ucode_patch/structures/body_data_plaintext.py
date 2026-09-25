#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Non-encrypted body data.
"""

from __future__ import annotations

from dataclasses import dataclass

from amd_ucode_patch.structures.body_data import BodyData


@dataclass
class PlaintextBodyData(BodyData):
    """Non-encrypted body contents, kept verbatim and not yet modelled."""

    is_encrypted = False

    #: The contents, kept verbatim and not yet modelled.
    unknown0: bytes

    def to_bytes(self) -> bytes:
        """Serialize the body data back to its exact byte encoding."""
        return self.unknown0
