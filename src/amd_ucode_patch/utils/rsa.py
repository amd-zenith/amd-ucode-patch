#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Minimal RSA signature verification helpers (textbook RSA + PKCS#1 v1.5 type 1).
"""

RSA_EXPONENT_F4 = 0x10001


def pkcs1_v15_pad_type1(payload: bytes, size: int) -> bytes:
    """
    Build a PKCS#1 v1.5 type-1 padded block:
    ``00 01 FF..FF 00 || payload``.
    """
    if size < len(payload) + 11:
        raise ValueError("RSA size too small for PKCS#1 v1.5 padding")
    ff_len = size - len(payload) - 3
    return b"\x00\x01" + (b"\xff" * ff_len) + b"\x00" + payload


def pkcs1_v15_unpad_type1(block: bytes) -> bytes | None:
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


def rsa_public_op(signature: bytes, modulus: bytes, exponent: int = RSA_EXPONENT_F4) -> bytes:
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


def recover_pkcs1_v15_payload(signature: bytes, modulus: bytes, exponent: int = RSA_EXPONENT_F4) -> bytes | None:
    """
    Recover the digest this signature commits to, using only the embedded
    public ``modulus`` (no CMAC key required): compute
    ``signature ^ 0x10001 mod modulus`` and strip the PKCS#1 v1.5 padding.

    Returns the recovered payload — the 16-byte AES-CMAC AMD signed — or
    ``None`` if the recovered block is not well-formed PKCS#1 v1.5 (e.g. a
    corrupt signature or wrong modulus).
    """
    try:
        block = rsa_public_op(signature, modulus, exponent)
    except ValueError:
        return None
    return pkcs1_v15_unpad_type1(block)


def verify_pkcs1_v15_payload(signature: bytes, modulus: bytes, digest: bytes,
                             exponent: int = RSA_EXPONENT_F4) -> bool:
    """
    Verify a PKCS#1 v1.5 signature whose padded payload is the raw ``digest``
    (no DigestInfo ASN.1 wrapper, as AMD uses a bare 16-byte CMAC).
    """
    payload = recover_pkcs1_v15_payload(signature, modulus, exponent)
    return payload is not None and payload == digest


def sign_pkcs1_v15_payload(digest: bytes, modulus: bytes, private: bytes) -> bytes:
    """
    Create a PKCS#1 v1.5 signature over a precomputed ``digest`` using
    textbook RSA private-key operation ``m^d mod n``.
    """
    n = int.from_bytes(modulus, "big")
    d = int.from_bytes(private, "big")
    m = int.from_bytes(pkcs1_v15_pad_type1(digest, len(modulus)), "big")
    if n == 0:
        raise ValueError("modulus cannot be zero")
    if m >= n:
        raise ValueError("padded message is not smaller than modulus")
    return pow(m, d, n).to_bytes(len(modulus), "big")
