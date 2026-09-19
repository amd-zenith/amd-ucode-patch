#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The common interface of the signature block.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar


class Signature(ABC):
    """A signature-slot block, in whatever layout its family uses."""

    #: Size of the block in bytes. Set by each concrete class.
    SIZE: ClassVar[int]

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> "Signature":
        """Parse the block from the first :data:`SIZE` bytes of ``data``."""

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize the block back to its exact byte encoding."""
