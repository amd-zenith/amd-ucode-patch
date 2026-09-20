#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests for the body section: everything after the header.

The body header (signed patches) is modelled, as are the match registers a
plaintext body opens with; the rest of the body stays verbatim. These tests pin
the boundary the header hands over, the byte-exact round-trip, where the body
header is split off, and which families claim a match-register count.
"""

import struct
from pathlib import Path

import pytest

from amd_ucode_patch.structures.body import Body
from amd_ucode_patch.structures.body_data_encrypted import EncryptedBodyData
from amd_ucode_patch.structures.body_data_plaintext import PlaintextBodyData
from amd_ucode_patch.structures.body_data_fam0fto12 import BodyDataFam0fto12
from amd_ucode_patch.structures.body_data_registry import (
    body_data_from_bytes,
    is_modelled,
)
from amd_ucode_patch.structures.body_header import BodyHeader
from amd_ucode_patch.structures.match_registers import MatchRegisters
from amd_ucode_patch.structures.patch import Patch

#: A family whose body is opaque, and one whose body begins with a body header.
_OPAQUE_FAMILY, _BODY_HEADER_FAMILY = 0x14, 0x17
#: The families whose body opens with match registers, and one of them.
_MATCH_FAMILIES = frozenset({0x0F, 0x10, 0x11, 0x12})
_MATCH_FAMILY = 0x10


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


def test_encrypted_flag_matches_what_the_patch_declares(patch_file: Path):
    """
    A body is encrypted exactly when the patch says so -- in its body header
    where there is one, or in the header data on the families that carry the
    signal there instead (Bobcat and Bulldozer, which have no body header).
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    bh = patch.body.body_header
    declared = patch.header.data.is_encrypted
    expected = (declared if declared is not None
                else (bh is not None and bool(bh.encrypted)))
    assert patch.body.is_encrypted == expected


def test_a_header_declared_encrypted_body_is_opaque(patch_file: Path):
    """Declared in the header means the body data is the opaque class."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.header.data.is_encrypted is not True:
        pytest.skip("header does not declare the body encrypted")
    assert isinstance(patch.body.body_data, EncryptedBodyData)
    assert patch.body.is_encrypted


# -- the match registers a plaintext body opens with --

def _match_body(registers: list[int]) -> bytes:
    """A body of ``registers`` match registers followed by some microcode."""
    return struct.pack(f"<{len(registers)}I", *registers) + b"microcode"


def test_match_registers_are_split_off():
    raw = _match_body(list(range(8)))
    body = Body.from_bytes(raw, _MATCH_FAMILY)
    assert isinstance(body.body_data, BodyDataFam0fto12)
    registers = body.body_data.match_registers
    assert isinstance(registers, MatchRegisters)
    assert registers.values == list(range(8))
    assert registers.count == 8
    assert body.body_data.op_triads == b"microcode"
    assert body.to_bytes() == raw


def test_match_register_edit_persists():
    body = Body.from_bytes(_match_body([0] * 8), _MATCH_FAMILY)
    body.body_data.match_registers.values[0] = 0xDEADBEEF
    reparsed = Body.from_bytes(body.to_bytes(), _MATCH_FAMILY)
    assert reparsed.body_data.match_registers.values[0] == 0xDEADBEEF


def test_unmodelled_family_keeps_the_body_verbatim():
    """
    A same-shaped body of a family with no body model is not sliced: it gets
    the plaintext model, which has no match registers to speak of at all.
    """
    raw = _match_body(list(range(8)))
    body = Body.from_bytes(raw, _OPAQUE_FAMILY)
    assert isinstance(body.body_data, PlaintextBodyData)
    assert not hasattr(body.body_data, "match_registers")
    assert body.body_data.unknown0 == raw


def test_short_body_is_refused():
    """
    Too few bytes to hold the registers its family declares: the body is
    malformed and refused, as every other section does with a short buffer.
    """
    with pytest.raises(ValueError):
        Body.from_bytes(b"short", _MATCH_FAMILY)


def test_truncated_patch_of_a_match_family_is_refused():
    """
    The whole-file path, and the error contract: a short body raises
    ``ValueError`` like the rest of the parser, not the bare ``struct.error``
    that reading it unguarded would produce.
    """
    with pytest.raises(ValueError):
        Patch.from_bytes(bytes(32) + b"12345678")


def test_an_unmodelled_family_accepts_any_length():
    """Only a modelled body can be unmet, so these families never refuse."""
    assert Body.from_bytes(b"short", _OPAQUE_FAMILY).to_bytes() == b"short"
    assert Body.from_bytes(b"", _OPAQUE_FAMILY).to_bytes() == b""


def test_a_body_that_exactly_fits_the_registers_is_decoded():
    """The boundary: nothing past the registers is not the same as too short."""
    raw = struct.pack("<8I", *range(8))
    body = Body.from_bytes(raw, _MATCH_FAMILY)
    assert body.body_data.match_registers.values == list(range(8))
    assert body.body_data.op_triads == b""
    assert body.to_bytes() == raw


def test_only_a_modelled_body_can_be_unmet():
    """
    The two cases a short body can land in: a family whose body is modelled
    refuses it, one with no model keeps it verbatim.
    """
    assert MatchRegisters.count_for_family(_MATCH_FAMILY) > 0
    assert MatchRegisters.count_for_family(_OPAQUE_FAMILY) == 0
    with pytest.raises(ValueError):
        Body.from_bytes(b"short", _MATCH_FAMILY)
    assert Body.from_bytes(b"short", _OPAQUE_FAMILY).to_bytes() == b"short"


def test_registry_picks_the_model_by_family():
    """
    An encrypted body is opaque whatever its family; a plaintext one gets its
    family's body model, or the unmodelled plaintext body when it has none.
    """
    raw = _match_body(list(range(8)))
    assert isinstance(body_data_from_bytes(_MATCH_FAMILY, True, raw), EncryptedBodyData)
    modelled = body_data_from_bytes(_MATCH_FAMILY, False, raw)
    assert isinstance(modelled, BodyDataFam0fto12)
    assert modelled.match_registers.values == list(range(8))
    assert isinstance(body_data_from_bytes(_OPAQUE_FAMILY, False, raw), PlaintextBodyData)


@pytest.mark.parametrize("family", [0x0F, 0x10, 0x11, 0x12])
def test_registry_models_the_match_register_families(family):
    assert is_modelled(family)


@pytest.mark.parametrize("family", [0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x99])
def test_registry_leaves_every_other_family_unmodelled(family):
    assert not is_modelled(family)


# -- corpus-backed --

def test_match_registers_are_addresses_or_sentinels(patch_file: Path):
    """
    What makes these match registers and not just the first 32 bytes: every
    slot is either a microcode ROM address or the 0xffffffff unused marker.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.header.patch_level.family not in _MATCH_FAMILIES:
        pytest.skip("family has no body model of its own")
    registers = patch.body.body_data.match_registers
    assert registers.count == 8
    assert all(a == MatchRegisters.UNUSED_ADDRESS or a < 0x2000
               for a in registers.addresses)
    # The array is what the body opens with, so its size is where the triads start.
    assert registers.size == 32
    assert patch.body.body_data.to_bytes()[registers.size:] == patch.body.body_data.op_triads


def test_only_the_modelled_families_decode_match_registers(patch_file: Path):
    """Every other corpus body keeps all of its bytes verbatim or opaque."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.header.patch_level.family in _MATCH_FAMILIES:
        pytest.skip("family has a body model of its own")
    if patch.body.is_encrypted:
        pytest.skip("encrypted bodies are opaque")
    assert isinstance(patch.body.body_data, PlaintextBodyData)
    assert not hasattr(patch.body.body_data, "match_registers")


def test_the_header_signal_is_tri_state(patch_file: Path):
    """
    ``None`` is not ``False``: a format with no encrypted flag in its header
    says nothing, and the body header decides instead.

    The two never both speak -- a header only carries the flag where there is
    no body header to carry it. Neither speaking is fine: the triad families
    are never encrypted and say so nowhere.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    declared = patch.header.data.is_encrypted
    assert declared is None or isinstance(declared, bool)
    if declared is not None:
        assert patch.body.body_header is None


def test_a_silent_header_leaves_the_body_header_in_charge():
    """A header with no opinion must not be read as 'plaintext'."""
    header = bytearray(BodyHeader.SIZE)
    header[1] = 1                                      # offset 1 is the flag
    raw = bytes(header) + b"payload"
    assert Body.from_bytes(raw, _BODY_HEADER_FAMILY).is_encrypted
    assert Body.from_bytes(raw, _BODY_HEADER_FAMILY, None).is_encrypted


def test_an_explicit_header_verdict_wins():
    """Where the header does speak, it decides, body header or not."""
    assert Body.from_bytes(b"payload", _OPAQUE_FAMILY, True).is_encrypted
    assert not Body.from_bytes(b"payload", _OPAQUE_FAMILY, False).is_encrypted


# -- the triad checksum the header records --

def test_op_triad_checksum_sums_the_triads():
    raw = struct.pack("<8I", *range(8)) + struct.pack("<3I", 1, 2, 0xFFFFFFFF)
    body = Body.from_bytes(raw, _MATCH_FAMILY)
    assert body.body_data.op_triad_checksum == (1 + 2 + 0xFFFFFFFF) & 0xFFFFFFFF


def test_op_triad_checksum_wraps_at_32_bits():
    raw = struct.pack("<8I", *range(8)) + struct.pack("<2I", 0xFFFFFFFF, 2)
    body = Body.from_bytes(raw, _MATCH_FAMILY)
    assert body.body_data.op_triad_checksum == 1


def test_op_triad_checksum_of_an_empty_array_is_zero():
    body = Body.from_bytes(struct.pack("<8I", *range(8)), _MATCH_FAMILY)
    assert body.body_data.op_triads == b""
    assert body.body_data.op_triad_checksum == 0


def test_op_triad_checksum_refuses_a_partial_word():
    """A real triad array is 28 bytes per triad, so always whole u32 words."""
    body = Body.from_bytes(_match_body(list(range(8))), _MATCH_FAMILY)
    assert len(body.body_data.op_triads) % 4          # b"microcode" is 9 bytes
    with pytest.raises(ValueError):
        body.body_data.op_triad_checksum


def test_op_triad_checksum_tracks_an_edit():
    raw = struct.pack("<8I", *range(8)) + struct.pack("<2I", 1, 2)
    body = Body.from_bytes(raw, _MATCH_FAMILY)
    before = body.body_data.op_triad_checksum
    body.body_data.op_triads = struct.pack("<2I", 1, 3)
    assert body.body_data.op_triad_checksum == before + 1


# -- corpus-backed --

def test_body_checksum_matches_the_header(patch_file: Path):
    """
    The cross-check the two sections make on each other: the header stores the
    u32 sum of exactly the region the body model carves out as the triads.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    if not isinstance(patch.body.body_data, BodyDataFam0fto12):
        pytest.skip("family has no body model of its own")
    assert (patch.body.body_data.op_triad_checksum
            == patch.header.data.op_triad_checksum)


def test_a_flipped_bit_in_the_triads_breaks_the_checksum(patch_file: Path):
    """The check has to be sensitive to the data it covers."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    if not isinstance(patch.body.body_data, BodyDataFam0fto12):
        pytest.skip("family has no body model of its own")
    blob = bytearray(patch.body.body_data.op_triads)
    blob[0] ^= 0x01
    patch.body.body_data.op_triads = bytes(blob)
    assert (patch.body.body_data.op_triad_checksum
            != patch.header.data.op_triad_checksum)
