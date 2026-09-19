#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The top-level container for a full AMD microcode patch file.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from amd_ucode_patch.structures.body import Body
from amd_ucode_patch.structures.header import Header
from amd_ucode_patch.structures.signature_fam17plus import SignatureFam17Plus


@dataclass
class Patch:
    """A full AMD microcode patch, as read from a single patch file."""

    #: The header: fixed core plus the signature block on signed patches.
    header: Header
    #: The patch body: everything after the header.
    body: Body

    @classmethod
    def from_bytes(cls, data: bytes) -> "Patch":
        """Parse a patch from its raw byte encoding."""
        data = bytes(data)
        header = Header.from_bytes(data)
        body = Body.from_bytes(data[header.size:], header.patch_level.family)
        return cls(header=header, body=body)

    @classmethod
    def from_file(cls, path: str | Path) -> "Patch":
        """Read and parse a patch from ``path``."""
        return cls.from_bytes(Path(path).read_bytes())

    def to_bytes(self) -> bytes:
        """Serialize the patch back to its exact byte encoding."""
        return self.header.to_bytes() + self.body.to_bytes()

    def to_file(self, path: str | Path) -> None:
        """Write the patch's byte encoding to ``path``."""
        Path(path).write_bytes(self.to_bytes())

    def signature_verifies(self, cmac_key: bytes) -> bool | None:
        """
        Whether the signature covers this patch's body under ``cmac_key``, or
        ``None`` when the patch has no verifiable (RSA) signature. Either it
        carries none, or it carries the family 0x16 block, which is not RSA.

        The signed region is the body: everything after the header, which on a
        signed patch means everything after the signature block.
        """
        signature = self.header.signature
        if not isinstance(signature, SignatureFam17Plus):
            return None
        return signature.verify(self.body.to_bytes(), cmac_key)

    @property
    def sha256(self) -> str:
        """SHA-256 of the whole patch, as a hex string, over its current bytes."""
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @property
    def name_canonical(self) -> str:
        """
        The canonical filename for this patch, in the amd-ucode-collection
        scheme::

            family<ff>_cpuid<CPUID>_rev<rev>_date<yyyymmdd>_enc<ee>_sha<hash12>.bin

        ``family`` comes from the patch level, the authoritative family signal.
        On a few pre-Zen patches this disagrees with the CPUID field, whose value
        is an equivalence id rather than a packed CPUID and can decode to the
        wrong family (e.g. a Llano patch whose id ``0x1200`` reads as family
        0x10); the name follows the patch level, so it can differ from the
        collection's own name for those. ``cpuid`` is the CPUID field as stored.
        ``_enc`` is the body header's ``encrypted`` flag, defaulting to ``00``
        when the patch carries no body header.
        """
        cpuid = self.header.data.cpuid
        date = self.header.date
        encrypted = (
            self.body.body_header.encrypted
            if self.body.body_header is not None
            else 0
        )
        return (
            f"family{self.header.patch_level.family:02x}"
            f"_cpuid{cpuid.cpuid_signature:08X}"
            f"_rev{self.header.patch_level}"
            f"_date{date.year:04}{date.month:02}{date.day:02}"
            f"_enc{encrypted:02}"
            f"_sha{self.sha256[:12]}.bin"
        )
