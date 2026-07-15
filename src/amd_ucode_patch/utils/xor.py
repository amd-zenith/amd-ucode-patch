#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Byte-string XOR helpers.
"""


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Return the byte-wise XOR of ``a`` and ``b``.

    Both operands must be the same length; a mismatch raises ``ValueError``.
    Works on any equal-length byte sequences (``bytes``, ``bytearray``,
    ``memoryview`` slices), not just 16-byte blocks.
    """
    if len(a) != len(b):
        raise ValueError(f"xor operands differ in length: {len(a)} != {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))
