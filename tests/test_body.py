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
from amd_ucode_patch.structures.body_data_fam14to15 import BodyDataFam14to15
from amd_ucode_patch.structures.body_data_fam17plus import BodyDataFam17Plus
from amd_ucode_patch.structures.body_data_registry import (
    body_data_from_bytes,
    is_modelled,
)
from amd_ucode_patch.structures.body_header import BodyHeader
from amd_ucode_patch.structures.match_registers import MatchRegisters
from amd_ucode_patch.structures.patch import Patch
from amd_ucode_patch.structures.patch_level import PatchLevel

#: A family with no body model at all, and one whose body begins with a body
#: header. Every real family now has one or the other, so the unmodelled case
#: needs a family that is not real silicon. Jaguar (0x16) carries a body header
#: and still has no body model, which is what the body-header tests want.
_OPAQUE_FAMILY, _BODY_HEADER_FAMILY = 0x99, 0x16
#: The families whose body opens with match registers, and one of them.
_MATCH_FAMILIES = frozenset({0x0F, 0x10, 0x11, 0x12})
_MATCH_FAMILY = 0x10
#: The families whose body opens with a frame, and one of them.
_FRAME_FAMILIES = frozenset({0x14, 0x15})
_FRAME_FAMILY = 0x14
#: The Zen families, whose body opens with match registers then quads, and one
#: of them. They pack two addresses per register, unlike _MATCH_FAMILIES.
_QUAD_FAMILIES = frozenset({0x17, 0x19, 0x1A})
_QUAD_FAMILY = 0x19


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


@pytest.mark.parametrize(
    "family", [0x0F, 0x10, 0x11, 0x12, 0x14, 0x15, 0x17, 0x19, 0x1A])
def test_registry_models_the_families_with_a_body_layout(family):
    assert is_modelled(family)


@pytest.mark.parametrize("family", [0x16, 0x99])
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
    if patch.header.patch_level.family in _MATCH_FAMILIES | _QUAD_FAMILIES:
        pytest.skip("family has a body model of its own")
    if patch.body.is_encrypted:
        pytest.skip("encrypted bodies are opaque")
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


# -- the triad geometry the count is expressed in --

def test_triad_geometry_is_three_ops_and_a_sequence_word():
    g = BodyDataFam0fto12.GEOMETRY
    assert (g.op_size, g.ops_per_group, g.sequence_word_size) == (8, 3, 4)
    assert g.group_size == 28


def _triads(count: int) -> bytes:
    """A body of eight match registers followed by ``count`` whole triads."""
    return struct.pack("<8I", *range(8)) + bytes(count * BodyDataFam0fto12.GEOMETRY.group_size)


def test_op_triad_count_is_derived_from_the_array():
    body = Body.from_bytes(_triads(5), _MATCH_FAMILY)
    assert body.body_data.op_triad_count == 5
    assert body.body_data.holds_whole_triads


def test_an_empty_array_holds_no_triads():
    body = Body.from_bytes(struct.pack("<8I", *range(8)), _MATCH_FAMILY)
    assert body.body_data.op_triad_count == 0
    assert body.body_data.holds_whole_triads


def test_a_partial_triad_is_not_whole():
    body = Body.from_bytes(_triads(3) + b"leftover", _MATCH_FAMILY)
    assert not body.body_data.holds_whole_triads
    assert body.body_data.op_triad_count == 3        # floor: the whole ones


# -- corpus-backed --

def test_body_triad_count_matches_the_header(patch_file: Path):
    """
    The geometry cross-check: the array the body carves out is exactly as many
    whole triads as the header says, with nothing left over.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    body_data = patch.body.body_data
    if not isinstance(body_data, BodyDataFam0fto12):
        pytest.skip("family has no body model of its own")
    assert body_data.holds_whole_triads
    assert body_data.op_triad_count == patch.header.data.op_triad_count
    assert (len(body_data.op_triads)
            == patch.header.data.op_triad_count * BodyDataFam0fto12.GEOMETRY.group_size)


def test_the_whole_file_is_accounted_for(patch_file: Path):
    """
    Nothing is unexplained on these families: the core header, the match
    registers and the triads add up to the file.
    """
    raw = patch_file.read_bytes()
    patch = Patch.from_bytes(raw)
    body_data = patch.body.body_data
    if not isinstance(body_data, BodyDataFam0fto12):
        pytest.skip("family has no body model of its own")
    assert (len(raw) == patch.header.size
            + body_data.match_registers.size
            + patch.header.data.op_triad_count * BodyDataFam0fto12.GEOMETRY.group_size)


# -- the frame families 0x14 and 0x15 open their body with --

def _frame(patch_level: int, tag: bytes = b"12345678", reserved: int = 0) -> bytes:
    """A body frame followed by some microcode."""
    return tag + struct.pack("<II", reserved, patch_level) + b"microcode"


def test_frame_is_split_off():
    raw = _frame(0x05000001)
    body = Body.from_bytes(raw, _FRAME_FAMILY)
    assert isinstance(body.body_data, BodyDataFam14to15)
    assert body.body_data.unknown0 == b"12345678" + struct.pack("<I", 0)
    assert body.body_data.patch_level.value == 0x05000001
    assert body.body_data.unknown1 == b"microcode"
    assert body.to_bytes() == raw


def test_frame_edit_persists():
    body = Body.from_bytes(_frame(0x05000001), _FRAME_FAMILY)
    body.body_data.patch_level.value = 0x05000002
    reparsed = Body.from_bytes(body.to_bytes(), _FRAME_FAMILY)
    assert reparsed.body_data.patch_level.value == 0x05000002


def test_a_body_too_short_for_the_frame_is_refused():
    with pytest.raises(ValueError):
        Body.from_bytes(bytes(BodyDataFam14to15.FRAME_SIZE - 1), _FRAME_FAMILY)


def test_a_body_that_exactly_fits_the_frame_is_decoded():
    raw = b"12345678" + struct.pack("<II", 0, 0x05000001)
    body = Body.from_bytes(raw, _FRAME_FAMILY)
    assert body.body_data.unknown1 == b""
    assert body.to_bytes() == raw


def test_frame_is_readable_only_when_both_halves_hold():
    level = PatchLevel(value=0x05000001)
    readable = BodyDataFam14to15.frame_is_readable
    assert readable(_frame(0x05000001), level)
    # a non-zero reserved word, as ciphertext would give
    assert not readable(_frame(0x05000001, reserved=1), level)
    # a mirror that names a different patch
    assert not readable(_frame(0x05000002), level)
    # too short to hold a frame at all
    assert not readable(b"short", level)


# -- corpus-backed --

def test_the_frame_families_decode_their_frame(patch_file: Path):
    """The mirror is the anchor: it equals the header's patch level, 9/9."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    body_data = patch.body.body_data
    if not isinstance(body_data, BodyDataFam14to15):
        pytest.skip("family has no body frame, or its body is encrypted")
    assert body_data.patch_level.value == patch.header.patch_level.value


def test_the_frame_agrees_with_the_encrypted_flag(patch_file: Path):
    """
    The cross-check the frame exists to provide: it sits inside the encrypted
    region, so it decodes exactly when the header says the body is plaintext.
    Two independent signals, and they must never disagree.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    declared = patch.header.data.is_encrypted
    if declared is None:
        pytest.skip("this format carries no encrypted flag in its header")
    readable = BodyDataFam14to15.frame_is_readable(
        patch.body.to_bytes(), patch.header.patch_level)
    assert readable is not declared


# -- the Zen families 0x17, 0x19 and 0x1a: match registers then quads --

#: Quads each Zen family's body holds.
_QUAD_COUNTS = {0x17: 64, 0x19: 128, 0x1A: 370}
#: Match registers each Zen family's body opens with.
_ZEN_REGISTERS = {0x17: 22, 0x19: 38, 0x1A: 60}


def _quad_body(quads: int, family: int = _QUAD_FAMILY) -> bytes:
    """
    A whole Zen body: the body header these families carry (left zeroed, so
    the patch reads as plaintext), the family's match registers, then ``quads``
    whole quads.
    """
    count = _ZEN_REGISTERS[family]
    return (bytes(BodyHeader.SIZE)
            + struct.pack(f"<{count}I", *range(count))
            + bytes(quads * BodyDataFam17Plus.GEOMETRY.group_size))


def test_zen_match_registers_are_split_off():
    body = Body.from_bytes(_quad_body(3), _QUAD_FAMILY)
    assert isinstance(body.body_data, BodyDataFam17Plus)
    registers = body.body_data.match_registers
    assert registers.count == _ZEN_REGISTERS[_QUAD_FAMILY]
    assert registers.values == list(range(_ZEN_REGISTERS[_QUAD_FAMILY]))
    assert registers.size == _ZEN_REGISTERS[_QUAD_FAMILY] * 4


def test_zen_quad_count_is_derived_from_the_array():
    body = Body.from_bytes(_quad_body(5), _QUAD_FAMILY)
    assert body.body_data.op_quad_count == 5
    assert body.body_data.holds_whole_quads


def test_a_partial_zen_quad_is_not_whole():
    body = Body.from_bytes(_quad_body(2) + b"x", _QUAD_FAMILY)
    assert body.body_data.op_quad_count == 2
    assert not body.body_data.holds_whole_quads


def test_a_zen_body_with_no_quads_is_still_valid():
    body = Body.from_bytes(_quad_body(0), _QUAD_FAMILY)
    assert body.body_data.op_quads == b""
    assert body.body_data.op_quad_count == 0
    assert body.body_data.holds_whole_quads


def test_zen_body_roundtrips():
    raw = _quad_body(4)
    assert Body.from_bytes(raw, _QUAD_FAMILY).to_bytes() == raw


def test_a_short_zen_body_is_refused():
    """Too few bytes to hold the registers the family declares."""
    with pytest.raises(ValueError):
        Body.from_bytes(b"short", _QUAD_FAMILY)


@pytest.mark.parametrize("family", sorted(_QUAD_FAMILIES))
def test_every_zen_family_uses_the_quad_geometry(family):
    body = Body.from_bytes(_quad_body(1, family), family)
    assert body.body_data.GEOMETRY.group_size == 36
    assert body.body_data.op_quad_count == 1


# -- corpus-backed --

def test_zen_bodies_are_registers_then_whole_quads(patch_file: Path):
    """
    A decrypted Zen body is exactly its match registers plus the quad array,
    with nothing left over and the quad count its family uses.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    family = patch.header.patch_level.family
    if family not in _QUAD_FAMILIES:
        pytest.skip("not a Zen family")
    if patch.body.is_encrypted:
        pytest.skip("encrypted bodies are opaque")
    body_data = patch.body.body_data
    assert isinstance(body_data, BodyDataFam17Plus)
    assert body_data.match_registers.count == _ZEN_REGISTERS[family]
    assert body_data.holds_whole_quads
    assert body_data.op_quad_count == _QUAD_COUNTS[family]
    assert (body_data.match_registers.size + len(body_data.op_quads)
            == len(body_data.to_bytes()))


def test_zen_match_registers_decode_as_packed_pairs(patch_file: Path):
    """
    Every address a decrypted Zen body names fits the 13 bits the packed pair
    gives it, and the four top bits of each register stay clear.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.header.patch_level.family not in _QUAD_FAMILIES:
        pytest.skip("not a Zen family")
    if patch.body.is_encrypted:
        pytest.skip("encrypted bodies are opaque")
    registers = patch.body.body_data.match_registers
    assert len(registers.addresses) == 2 * registers.count
    assert all(address <= 0x1FFF for address in registers.addresses)
    assert set(registers.used) <= set(registers.addresses)
