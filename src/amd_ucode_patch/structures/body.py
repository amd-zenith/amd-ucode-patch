#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The patch body.
"""

from __future__ import annotations

from dataclasses import dataclass

from amd_ucode_patch.structures.body_data import BodyData
from amd_ucode_patch.structures.body_data_registry import body_data_from_bytes
from amd_ucode_patch.structures.body_header import BodyHeader


@dataclass
class Body:
    """
    The patch body: an optional :class:`BodyHeader` followed by the
    :class:`BodyData`.

    The body header's ``encrypted`` flag selects the kind of body data: opaque
    when set, plaintext (a modelling target) otherwise.
    """

    #: The body header, on formats that carry one; ``None`` otherwise.
    body_header: BodyHeader | None
    #: The contents past the header.
    body_data: BodyData

    @classmethod
    def from_bytes(cls, data: bytes, family: int,
                   encrypted: bool = False) -> "Body":
        """
        Parse the body from ``data``, which is the body and nothing else, using
        the CPU ``family`` to pick the layout.

        :class:`BodyHeader` decides whether ``family`` carries a body header.
        The remainder is handed to the body data registry, which picks the
        correct representation.

        The encrypted signal comes from wherever the format keeps it: the body
        header's flag, or ``encrypted`` signal that may come from the patch header.
        """
        data = bytes(data)
        body_header = BodyHeader.from_bytes(data, family)
        remainder = data[BodyHeader.SIZE:] if body_header is not None else data
        encrypted = encrypted or (
            body_header is not None and bool(body_header.encrypted)
        )
        body_data = body_data_from_bytes(family, encrypted, remainder)
        return cls(
            body_header=body_header,
            body_data=body_data,
        )

    @property
    def is_encrypted(self) -> bool:
        """Whether the body data is encrypted (and so cannot be modelled)."""
        return self.body_data.is_encrypted

    def to_bytes(self) -> bytes:
        """Serialize the body back to its exact byte encoding."""
        prefix = self.body_header.to_bytes() if self.body_header is not None else b""
        return prefix + self.body_data.to_bytes()
