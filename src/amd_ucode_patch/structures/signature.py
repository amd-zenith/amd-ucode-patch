#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from amd_ucode_patch.utils.rsa import digest_recover, pkcs1_v15_verify


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

    def recover_digest(self) -> bytes | None:
        """
        Recover the digest this signature commits to, using only the embedded
        public ``modulus`` (no CMAC key required): compute
        ``signature ^ 0x10001 mod modulus`` and strip the PKCS#1 v1.5 padding.

        Returns the recovered payload — the 16-byte AES-CMAC AMD signed — or
        ``None`` if the recovered block is not well-formed PKCS#1 v1.5 (e.g. a
        corrupt signature or wrong modulus).
        """
        return digest_recover(self.signature, self.modulus)

    def verify(self, signed_region: bytes, cmac_key: bytes) -> bool:
        """
        Return ``True`` if this RSA signature, checked against the embedded
        ``modulus``, recovers the AES-CMAC of ``signed_region`` (the body:
        ``options`` + ``rev`` + match registers + opquads).

        Uses the Zen 1-4 CMAC key by default; Zen 5 uses a different, unpublished
        key, so Zen 5 patches will not verify unless the right ``cmac_key`` is
        supplied.
        """
        digest = CMAC.new(cmac_key, msg=signed_region, ciphermod=AES).digest()
        return pkcs1_v15_verify(self.signature, self.modulus, digest)
