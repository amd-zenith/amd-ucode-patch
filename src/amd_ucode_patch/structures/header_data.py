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

    @property
    def is_encrypted(self) -> bool | None:
        """
        Whether the header declares the body encrypted, or ``None`` when this
        format does not carry that signal in the header at all.

        ``None`` is not ``False``: it says the header has no opinion, so the
        body must be read some other way -- from its body header on the formats
        that have one. Only a format with no body header to carry the flag
        answers with a bool.
        """
        return None

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> "HeaderData":
        """Parse the header data from the first :data:`SIZE` bytes of ``data``."""

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize the header data back to its exact byte encoding."""
