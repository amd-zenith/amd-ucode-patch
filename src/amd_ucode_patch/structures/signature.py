#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass


@dataclass
class Signature:
    """
    Cryptographic signature block of a Zen (family >= 0x17) AMD microcode patch.

    It sits immediately after the 32-byte header core and is absent on pre-Zen
    patches. Layout (offsets are from the start of the patch)::

        offset  32  signature[256]  RSA-2048 signature (PKCS#1 v1.5, e=0x10001)
        offset 288  modulus[256]    RSA-2048 public key, embedded in the patch
        offset 544  check[256]      Montgomery helper derived from the modulus
    """

    SIG_SIZE = 256
    MODULUS_SIZE = 256
    CHECK_SIZE = 256
    SIZE = SIG_SIZE + MODULUS_SIZE + CHECK_SIZE

    signature: bytes
    modulus: bytes
    check: bytes

    @staticmethod
    def from_bytes(buf: bytes) -> "Signature":
        if len(buf) < Signature.SIZE:
            raise ValueError("not enough bytes for AMD signature block")
        return Signature(
            signature=buf[0:Signature.SIG_SIZE],
            modulus=buf[Signature.SIG_SIZE:Signature.SIG_SIZE + Signature.MODULUS_SIZE],
            check=buf[Signature.SIG_SIZE + Signature.MODULUS_SIZE:Signature.SIZE],
        )

    def to_bytes(self) -> bytes:
        return self.signature + self.modulus + self.check
