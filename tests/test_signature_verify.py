#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Signature checking: the RSA (family 0x17+) block against the body it covers.

AMD signs the AES-CMAC of the body rather than a hash of it, so there are two
distinct checks. ``recover_digest`` needs only the embedded modulus and says
whether the signature belongs to that key at all; :meth:`Patch.signature_verifies`
also needs a CMAC key and says whether the body is the one that was signed.

The family 0x16 block is a signature slot too, but not an RSA one, so it neither
recovers a digest nor verifies. No key is committed here, so the checks that need
one take the ``cmac_key`` fixture and skip unless ``$AMD_UCODE_CMAC_KEY`` supplies
it.
"""

from pathlib import Path

import pytest

from amd_ucode_patch.structures.patch import Patch
from amd_ucode_patch.structures.signature_fam16 import SignatureFam16
from amd_ucode_patch.structures.signature_fam17plus import SignatureFam17Plus

#: RSA-signed patches (family 0x17+) and family-0x16 signature-slot patches.
_RSA_SIGNED = 338
_FAM16_SIGNED = 14


def _rsa_signed(patch_file: Path) -> Patch | None:
    patch = Patch.from_bytes(patch_file.read_bytes())
    return patch if isinstance(patch.header.signature, SignatureFam17Plus) else None


def _verifying_patch(corpus_dir: Path, key: bytes) -> Patch:
    """The first corpus patch that verifies under ``key``."""
    for path in sorted(corpus_dir.glob("*.bin")):
        patch = Patch.from_bytes(path.read_bytes())
        if patch.signature_verifies(key) is True:
            return patch
    pytest.skip("no corpus patch verifies under the supplied CMAC key")


# -- the digest, recoverable from an RSA-signed patch alone --

def test_signature_belongs_to_its_embedded_modulus(patch_file: Path):
    """
    The key-free check: the signature unpads as PKCS#1 v1.5 under the modulus
    the patch carries. Random bytes pass this with negligible probability, so
    it is a real structural test rather than an entropy heuristic.
    """
    patch = _rsa_signed(patch_file)
    if patch is None:
        pytest.skip("not an RSA-signed patch")
    digest = patch.header.signature.recover_digest()
    assert digest is not None and len(digest) == 16


def test_recover_digest_rejects_a_foreign_modulus(patch_file: Path):
    """Swapping in another patch's modulus must stop the signature unpadding."""
    patch = _rsa_signed(patch_file)
    if patch is None:
        pytest.skip("not an RSA-signed patch")
    signature = patch.header.signature
    signature.modulus = bytes(reversed(signature.modulus))
    assert signature.recover_digest() is None


def test_signature_slot_counts(corpus_dir: Path):
    """How the corpus splits between RSA and family-0x16 signature slots."""
    rsa = fam16 = 0
    for path in sorted(corpus_dir.glob("*.bin")):
        signature = Patch.from_bytes(path.read_bytes()).header.signature
        rsa += isinstance(signature, SignatureFam17Plus)
        fam16 += isinstance(signature, SignatureFam16)
    assert (rsa, fam16) == (_RSA_SIGNED, _FAM16_SIGNED)


# -- verification against the body --

def test_patches_without_an_rsa_signature_report_none(patch_file: Path):
    """Unsigned and family-0x16 patches cannot be RSA-verified."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    if isinstance(patch.header.signature, SignatureFam17Plus):
        pytest.skip("RSA-signed patch")
    assert patch.signature_verifies(bytes(16)) is None


def test_a_real_key_verifies_real_patches(corpus_dir: Path, cmac_key: bytes):
    """
    The gate on the signed region: a correct key verifies whole patches only if
    the region the CMAC covers is exactly right. A region off by one byte, or
    one that included the signature block, would verify nothing at all.
    """
    verified = sum(Patch.from_bytes(p.read_bytes()).signature_verifies(cmac_key)
                   is True for p in sorted(corpus_dir.glob("*.bin")))
    assert verified > 0, (
        "no patch verified: either the supplied key signed none of this corpus, "
        "or the signed region is wrong"
    )


def test_a_tampered_body_fails_verification(corpus_dir: Path, cmac_key: bytes):
    """
    The check has to be sensitive to the body, not just to the signature block:
    one flipped bit anywhere in the signed region must fail it.
    """
    patch = _verifying_patch(corpus_dir, cmac_key)
    # Flip a byte in whichever field holds the body data's content.
    body_data = patch.body.body_data
    field = "data" if body_data.is_encrypted else "unknown0"
    blob = bytearray(getattr(body_data, field))
    blob[0] ^= 0xFF
    setattr(body_data, field, bytes(blob))
    assert patch.signature_verifies(cmac_key) is False
    # ... while the signature itself still belongs to its modulus
    assert patch.header.signature.recover_digest() is not None


def test_another_key_fails_verification(corpus_dir: Path, cmac_key: bytes):
    """
    A patch signed under one key fails verification under another but keeps a
    recoverable digest -- the distinction that separates "not my key" from
    "forged".
    """
    patch = _verifying_patch(corpus_dir, cmac_key)
    other_key = bytes([cmac_key[0] ^ 0xFF]) + cmac_key[1:]
    assert patch.signature_verifies(other_key) is False
    assert patch.header.signature.recover_digest() is not None
