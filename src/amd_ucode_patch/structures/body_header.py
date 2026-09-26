#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The common interface of the body header.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar


class BodyHeader(ABC):
    """
    The 8-byte body header of a signed patch, in whatever layout its family uses.

    Every layout opens with the same two flag bytes (``init_flag``, ``encrypted``)
    and closes with a copy of the header's patch level; families differ only in
    the two bytes between them (offset 2-3). The older signed families (Jaguar
    0x16, Zen 1-2 0x17, Zen 3-4 0x19) leave that span zero; Zen 5 (0x1a) fills it
    with a copy of the loader id (see :class:`BodyHeaderFam1a`).
    """

    #: Size of the body header. Identical in every known layout.
    SIZE: ClassVar[int] = 8

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> "BodyHeader":
        """Parse the body header from the first :data:`SIZE` bytes of ``data``."""

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize the body header back to its exact byte encoding."""
