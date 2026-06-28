#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Minimal RSA signature verification helpers (textbook RSA + PKCS#1 v1.5 type 1).

No private-key operations and no external dependencies: verification is just a
modular exponentiation (``pow``) plus unpadding, which is all that is needed to
check an AMD microcode patch signature against its embedded public modulus.
"""


def rsa_recover(signature: bytes, modulus: bytes, exponent: int = 0x10001) -> bytes:
    """
    Return the RSA-recovered block ``signature ** exponent mod modulus`` as a
    big-endian byte string the same width as ``modulus``.
    """
    n = int.from_bytes(modulus, "big")
    s = int.from_bytes(signature, "big")
    if n == 0 or s >= n:
        raise ValueError("signature is not a residue modulo the public modulus")
    m = pow(s, exponent, n)
    return m.to_bytes(len(modulus), "big")


def pkcs1_v15_unpad(block: bytes) -> bytes | None:
    """
    Strip PKCS#1 v1.5 block-type-1 padding (``00 01 FF..FF 00 || payload``) and
    return the payload, or ``None`` if the padding is malformed.
    """
    if len(block) < 11 or block[0] != 0x00 or block[1] != 0x01:
        return None
    i = 2
    while i < len(block) and block[i] == 0xFF:
        i += 1
    if i < 10 or i >= len(block) or block[i] != 0x00:
        return None
    return block[i + 1:]


def pkcs1_v15_verify(signature: bytes, modulus: bytes, digest: bytes,
                     exponent: int = 0x10001) -> bool:
    """
    Verify a PKCS#1 v1.5 signature whose padded payload is the raw ``digest``
    (no DigestInfo ASN.1 wrapper, as AMD uses a bare 16-byte CMAC).
    """
    try:
        block = rsa_recover(signature, modulus, exponent)
    except ValueError:
        return False
    payload = pkcs1_v15_unpad(block)
    return payload is not None and payload == digest
