#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The common interface of the body data.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BodyData(ABC):
    """The contents of a body past its header, in whatever form the format uses."""

    #: Whether the contents are encrypted (and so can only be raw bytes).
    is_encrypted: bool

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize the body data back to its exact byte encoding."""
