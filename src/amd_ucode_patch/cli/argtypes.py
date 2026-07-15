#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Argparse ``type=`` converters for hex-encoded key material shared by the
command line tools. Each raises ``argparse.ArgumentTypeError`` on malformed or
wrong-length input, which argparse renders as a usage error.
"""

import argparse


def parse_fixed_hex(value: str, nbytes: int, what: str) -> bytes:
    """
    Parse ``value`` as hex (an optional ``0x`` prefix is allowed) and require it
    to decode to exactly ``nbytes`` bytes. ``what`` names the field in error
    messages.
    """
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        data = bytes.fromhex(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{what} must be hexadecimal, got {value!r}")
    if len(data) != nbytes:
        raise argparse.ArgumentTypeError(f"{what} must be {nbytes} bytes ({2 * nbytes} hex chars), got {len(data)}")
    return data


def parse_key(value: str) -> bytes:
    """Parse a 16-byte AES-128 CMAC key from hex."""
    return parse_fixed_hex(value, 16, "key")


def parse_modulus(value: str) -> bytes:
    """Parse a 256-byte RSA modulus from hex."""
    return parse_fixed_hex(value, 256, "modulus")


def parse_private(value: str) -> bytes:
    """Parse a 256-byte RSA private exponent from hex."""
    return parse_fixed_hex(value, 256, "private exponent")


def parse_check(value: str) -> bytes:
    """Parse a 256-byte signature check (Montgomery helper) field from hex."""
    return parse_fixed_hex(value, 256, "check")
