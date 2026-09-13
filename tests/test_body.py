#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests for the body section: everything after the header.

The body header (signed patches) is modelled; the rest of the body stays
verbatim. These tests pin the boundary the header hands over, the byte-exact
round-trip, and where the body header is split off.
"""

from pathlib import Path

import pytest

from amd_ucode_patch.structures.body import Body
from amd_ucode_patch.structures.body_data_encrypted import EncryptedBodyData
from amd_ucode_patch.structures.body_data_plaintext import PlaintextBodyData
from amd_ucode_patch.structures.body_header import BodyHeader
from amd_ucode_patch.structures.patch import Patch

#: A family whose body is opaque, and one whose body begins with a body header.
_OPAQUE_FAMILY, _BODY_HEADER_FAMILY = 0x14, 0x17


def test_keeps_every_byte():
    raw = bytes(range(256))
    assert Body.from_bytes(raw, _OPAQUE_FAMILY).to_bytes() == raw


def test_accepts_an_empty_body():
    assert Body.from_bytes(b"", _OPAQUE_FAMILY).to_bytes() == b""


def test_copies_its_input():
    """A body must not alias a caller's mutable buffer."""
    buf = bytearray(b"body")
    body = Body.from_bytes(buf, _OPAQUE_FAMILY)
    buf[0] = 0xFF
    assert body.to_bytes() == b"body"


def test_edit_persists():
    body = Body.from_bytes(b"body", _OPAQUE_FAMILY)
    body.body_data.unknown0 = b"other"
    assert body.to_bytes() == b"other"


# -- corpus-backed --

def test_body_is_everything_after_the_header(patch_file: Path):
    """
    The boundary assertion: a header that claimed too many or too few bytes --
    on either the unsigned or the signed path -- would show up here.
    """
    raw = patch_file.read_bytes()
    patch = Patch.from_bytes(raw)
    assert patch.body.to_bytes() == raw[patch.header.size:]


def test_body_roundtrips_corpus(patch_file: Path):
    raw = patch_file.read_bytes()
    header = Patch.from_bytes(raw).header
    body = raw[header.size:]
    assert Body.from_bytes(body, header.patch_level.family).to_bytes() == body


# -- the body header, present on the RSA-signed patches --

def test_body_header_present_iff_signature_slot(patch_file: Path):
    """
    The body header sits right after the signature slot, so it is present on
    exactly the families that have one -- Jaguar (0x16) and Zen (0x17+).
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    has_signature = patch.header.signature is not None
    assert (patch.body.body_header is not None) == has_signature


def test_body_header_mirrors_the_patch_level(patch_file: Path):
    """The body header carries a copy of the header's patch level."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.body.body_header is None:
        pytest.skip("patch has no body header")
    assert patch.body.body_header.patch_level.value == patch.header.patch_level.value


def test_body_header_flags_are_zero_or_one(patch_file: Path):
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.body.body_header is None:
        pytest.skip("patch has no body header")
    assert patch.body.body_header.init_flag in (0, 1)
    assert patch.body.body_header.encrypted in (0, 1)


def test_opaque_family_keeps_the_whole_body():
    body = Body.from_bytes(b"the whole body", _OPAQUE_FAMILY)
    assert body.body_header is None
    assert body.to_bytes() == b"the whole body"


def test_body_header_family_splits_the_header_off():
    header = BodyHeader.from_bytes(bytes(BodyHeader.SIZE), _BODY_HEADER_FAMILY)
    raw = header.to_bytes() + b"microcode"
    body = Body.from_bytes(raw, _BODY_HEADER_FAMILY)
    assert body.body_header == header
    assert body.body_data.unknown0 == b"microcode"
    assert body.to_bytes() == raw


def test_body_header_from_bytes_returns_none_for_a_bodyless_family():
    assert BodyHeader.from_bytes(bytes(BodyHeader.SIZE), _OPAQUE_FAMILY) is None


# -- the encrypted / plaintext distinction --

def _body_with_encrypted(encrypted: int) -> Body:
    """A body-header-family body whose header sets the given encrypted flag."""
    header = bytearray(BodyHeader.SIZE)
    header[1] = encrypted                              # offset 1 is the flag
    return Body.from_bytes(bytes(header) + b"payload", _BODY_HEADER_FAMILY)


def test_encrypted_body_is_kept_opaque():
    body = _body_with_encrypted(1)
    assert isinstance(body.body_data, EncryptedBodyData)
    assert body.is_encrypted
    assert body.body_data.data == b"payload"
    assert body.to_bytes() == body.body_header.to_bytes() + b"payload"


def test_plaintext_body_goes_to_unknown0():
    body = _body_with_encrypted(0)
    assert isinstance(body.body_data, PlaintextBodyData)
    assert not body.is_encrypted
    assert body.body_data.unknown0 == b"payload"


def test_bodyless_family_is_plaintext():
    body = Body.from_bytes(b"whatever", _OPAQUE_FAMILY)
    assert isinstance(body.body_data, PlaintextBodyData)
    assert not body.is_encrypted
    assert body.body_header is None
    assert body.body_data.unknown0 == b"whatever"


def test_body_data_variants_roundtrip():
    assert EncryptedBodyData(b"x").to_bytes() == b"x"
    assert EncryptedBodyData(b"x").is_encrypted
    assert PlaintextBodyData(b"y").to_bytes() == b"y"
    assert not PlaintextBodyData(b"y").is_encrypted


def test_encrypted_flag_matches_the_body_header(patch_file: Path):
    """A body is encrypted exactly when its body header says so."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    bh = patch.body.body_header
    expected = bh is not None and bool(bh.encrypted)
    assert patch.body.is_encrypted == expected
