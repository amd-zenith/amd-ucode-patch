#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""AES-CMAC helpers shared by signature tooling."""

from Crypto.Cipher import AES
from Crypto.Hash import CMAC


def cmac_digest(message: bytes, key: bytes) -> bytes:
    """Return AES-128-CMAC over ``message`` using ``key``."""
    return CMAC.new(key, msg=message, ciphermod=AES).digest()
