#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests for the signature-slot blocks and their family dispatch."""

import json
import struct
from pathlib import Path

import pytest

from amd_ucode_patch.structures.signature import Signature
from amd_ucode_patch.structures.signature_fam16 import SignatureFam16
from amd_ucode_patch.structures.signature_fam17plus import SignatureFam17Plus
from amd_ucode_patch.structures.signature_registry import signature_class

_BASELINE = json.loads((Path(__file__).parent / "data" / "baseline.json").read_text())

#: Offsets of the patch level and the signature slot in a patch file.
_PATCH_LEVEL_OFF, _SIG_OFF = 4, 32


def _family(patch_file: Path) -> int:
    patch_level = struct.unpack_from("<I", patch_file.read_bytes(), _PATCH_LEVEL_OFF)[0]
    return 0xF + (patch_level >> 24)


# -- the registry: which family carries which block --

@pytest.mark.parametrize(("family", "cls"), [
    (0x16, SignatureFam16),
    (0x17, SignatureFam17Plus),
    (0x19, SignatureFam17Plus),
    (0x1A, SignatureFam17Plus),
])
def test_registry_maps_family_to_block(family, cls):
    assert signature_class(family) is cls
    assert issubclass(cls, Signature)


@pytest.mark.parametrize("family", [0x0F, 0x10, 0x11, 0x12, 0x14, 0x15, 0x99])
def test_registry_has_no_block_for_other_families(family):
    assert signature_class(family) is None


# -- the family 0x17+ RSA block --

def test_fam17plus_size_is_768():
    assert SignatureFam17Plus.SIZE == 768


def test_fam17plus_splits_fields():
    sig, mod, chk = bytes([1]) * 256, bytes([2]) * 256, bytes([3]) * 256
    block = SignatureFam17Plus.from_bytes(sig + mod + chk)
    assert (block.signature, block.modulus, block.check) == (sig, mod, chk)


def test_fam17plus_roundtrip_and_short_buffer():
    block_bytes = bytes(range(256)) * 3
    assert SignatureFam17Plus.from_bytes(block_bytes).to_bytes() == block_bytes
    with pytest.raises(ValueError):
        SignatureFam17Plus.from_bytes(bytes(SignatureFam17Plus.SIZE - 1))


# -- the family 0x16 opaque block --

def test_fam16_size_is_576():
    assert SignatureFam16.SIZE == 576


def test_fam16_is_kept_verbatim():
    block = bytes(range(256)) + bytes(range(256)) + bytes(range(64))
    parsed = SignatureFam16.from_bytes(block)
    assert parsed.data == block
    assert parsed.to_bytes() == block


def test_fam16_reads_only_its_block_and_rejects_short():
    block = bytes(SignatureFam16.SIZE)
    assert SignatureFam16.from_bytes(block + b"body").to_bytes() == block
    with pytest.raises(ValueError):
        SignatureFam16.from_bytes(bytes(SignatureFam16.SIZE - 1))


# -- corpus-backed --

def test_block_roundtrips_corpus(patch_file: Path):
    """Whatever block a family carries round-trips from the signature slot."""
    cls = signature_class(_family(patch_file))
    if cls is None:
        pytest.skip("family has no signature slot")
    block = patch_file.read_bytes()[_SIG_OFF:_SIG_OFF + cls.SIZE]
    assert cls.from_bytes(block).to_bytes() == block
