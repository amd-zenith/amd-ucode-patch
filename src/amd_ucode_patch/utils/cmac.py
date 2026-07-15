#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""AES-CMAC helpers shared by signature tooling."""

from Crypto.Cipher import AES
from Crypto.Hash import CMAC


def cmac_digest(message: bytes, key: bytes) -> bytes:
    """Return AES-128-CMAC over ``message`` using ``key``."""
    return CMAC.new(key, msg=message, ciphermod=AES).digest()


def gf128_double(block: bytes) -> bytes:
    """
    Double a 16-byte block in GF(2^128): a left shift by one bit, reduced modulo
    the CMAC polynomial (XOR ``0x87``) when the top bit overflows. This is the
    ``dbl`` operation from RFC 4493 used to derive the AES-CMAC subkeys K1 and K2.
    """
    out = bytearray(block)
    carry = out[0] >> 7
    for i in range(15):
        out[i] = ((out[i] << 1) & 0xFF) | (out[i + 1] >> 7)
    out[15] = ((out[15] << 1) & 0xFF) ^ (0x87 if carry else 0)
    return bytes(out)


def cmac_subkeys(key: bytes) -> tuple[bytes, bytes]:
    """
    Derive the AES-CMAC subkeys ``(K1, K2)`` from ``key`` per RFC 4493:
    ``L = AES_key(0^128)``, ``K1 = dbl(L)``, ``K2 = dbl(K1)``.
    """
    aes = AES.new(key, AES.MODE_ECB)
    subkey1 = gf128_double(aes.encrypt(b"\x00" * 16))
    subkey2 = gf128_double(subkey1)
    return subkey1, subkey2
