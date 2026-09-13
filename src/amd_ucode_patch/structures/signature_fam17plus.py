#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Signature block for family 0x17 and newer (Zen).

A 768-byte block: a 256-byte RSA-2048 signature, the 256-byte RSA public modulus
embedded in the patch, and a 256-byte Montgomery ``check`` helper derived from
the modulus. AMD signs the AES-CMAC of the body, so verifying needs a CMAC key
as well as the embedded modulus.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from amd_ucode_patch.structures.signature import Signature
from amd_ucode_patch.utils.cmac import cmac_digest
from amd_ucode_patch.utils.rsa import (
    recover_pkcs1_v15_payload,
    verify_pkcs1_v15_payload,
)


@dataclass
class SignatureFam17Plus(Signature):
    """The 768-byte Zen signature block (signature + modulus + check)."""

    SIG_SIZE: ClassVar[int] = 256
    MODULUS_SIZE: ClassVar[int] = 256
    CHECK_SIZE: ClassVar[int] = 256
    #: Total size of the block.
    SIZE: ClassVar[int] = SIG_SIZE + MODULUS_SIZE + CHECK_SIZE

    #: RSA-2048 signature (PKCS#1 v1.5, e=0x10001).
    signature: bytes
    #: RSA-2048 public modulus embedded in the patch.
    modulus: bytes
    #: Montgomery helper derived from the modulus.
    check: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignatureFam17Plus":
        """Parse the block from the first :data:`SIZE` bytes of ``data``."""
        if len(data) < cls.SIZE:
            raise ValueError(
                f"not enough bytes for the fam 0x17+ signature block: "
                f"got {len(data)}, need {cls.SIZE}"
            )
        mod_off = cls.SIG_SIZE
        check_off = cls.SIG_SIZE + cls.MODULUS_SIZE
        return cls(
            signature=bytes(data[0:mod_off]),
            modulus=bytes(data[mod_off:check_off]),
            check=bytes(data[check_off:cls.SIZE]),
        )

    def to_bytes(self) -> bytes:
        """Serialize the block back to its exact byte encoding."""
        return self.signature + self.modulus + self.check

    def recover_digest(self) -> bytes | None:
        """
        The digest this signature commits to, recovered with the embedded
        :attr:`modulus` alone and no CMAC key: ``signature ^ 0x10001 mod
        modulus``, stripped of its PKCS#1 v1.5 padding.

        ``None`` when the recovered block is not well-formed PKCS#1 v1.5, which
        means the signature does not belong to this modulus.
        """
        return recover_pkcs1_v15_payload(self.signature, self.modulus)

    def verify(self, signed_region: bytes, cmac_key: bytes) -> bool:
        """
        Whether this signature covers ``signed_region`` under ``cmac_key``.

        AMD signs the AES-CMAC of the region rather than a hash of it, so
        verifying needs a CMAC key as well as the embedded modulus. No key is
        shipped with this library; the caller supplies the one to check against.
        A ``False`` does not mean the patch is forged: one signed with a key
        other than the one supplied fails this while still being structurally
        valid, which :meth:`recover_digest` can tell apart.
        """
        digest = cmac_digest(signed_region, cmac_key)
        return verify_pkcs1_v15_payload(self.signature, self.modulus, digest)
