#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
from dataclasses import dataclass
from .patch_header import PatchHeader
from .body import Body


@dataclass
class Patch:
    header: PatchHeader
    body: Body


    @staticmethod
    def from_bytes(buf: bytes) -> "Patch":
        header = PatchHeader.from_bytes(buf)
        # Everything after the header is the signed body: the verified header
        # (options + rev, Zen only) plus the microcode itself.
        body = Body.from_bytes(buf[header.size:], family=header.cpuid.family)
        return Patch(header=header, body=body)

    def to_bytes(self) -> bytes:
        """The whole patch encoding: the header (with signature block, if any)
        followed by the signed body."""
        return self.header.to_bytes() + self.body.to_bytes()

    def signature_verifies(self, cmac_key: bytes) -> bool | None:
        """
        Whether the patch signature verifies against its embedded public key,
        using the provided CMAC key (see :data:`Signature.verify`).

        ``None`` for unsigned (pre-Zen) patches. A ``False`` result does not by
        itself mean the patch is forged: patches signed with a CMAC key this
        library does not ship -- Zen 5, and AMD's post-EntrySign patches that
        rotated the key -- also report ``False`` even though their RSA signature
        is structurally valid against the embedded modulus.
        """
        if self.header.signature is None:
            return None
        return self.header.signature.verify(self.body.to_bytes(), cmac_key)

    def sha256(self) -> bytes:
        """SHA-256 digest of the whole patch (header + body)."""
        return hashlib.sha256(self.to_bytes()).digest()

    def sha256_hex(self) -> str:
        """SHA-256 digest of the whole patch (header + body) as a hex string."""
        return hashlib.sha256(self.to_bytes()).hexdigest()
