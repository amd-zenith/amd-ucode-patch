#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The common interface of the header data.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar


class HeaderData(ABC):
    """
    The 22-byte header-data region, in whatever layout its format uses.
    """

    #: Size of the header-data region. Identical in every known format.
    SIZE: ClassVar[int] = 22

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> "HeaderData":
        """Parse the header data from the first :data:`SIZE` bytes of ``data``."""

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize the header data back to its exact byte encoding."""
