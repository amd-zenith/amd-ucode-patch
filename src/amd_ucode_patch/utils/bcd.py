#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Helpers for working with packed binary-coded-decimal (BCD) values, where each
nibble holds a single decimal digit (0-9). AMD microcode patch headers encode
their build date this way.
"""


def decode_bcd(value: int, num_nibbles: int) -> int:
    """
    Decode the low ``num_nibbles`` nibbles of a packed-BCD ``value`` into its
    decimal integer equivalent (e.g. ``0x2018 -> 2018``).
    """
    result = 0
    multiplier = 1
    for i in range(num_nibbles):
        result += ((value >> (i * 4)) & 0xF) * multiplier
        multiplier *= 10
    return result


def encode_bcd(value: int, num_nibbles: int) -> int:
    """
    Encode a decimal integer ``value`` into its packed-BCD equivalent across
    ``num_nibbles`` nibbles (e.g. ``2018 -> 0x2018``). Raises ``ValueError`` if
    ``value`` does not fit in ``num_nibbles`` decimal digits.
    """
    if value < 0 or value >= 10 ** num_nibbles:
        raise ValueError(f"{value} does not fit in {num_nibbles} BCD nibbles")
    result = 0
    for i in range(num_nibbles):
        result |= (value % 10) << (i * 4)
        value //= 10
    return result
