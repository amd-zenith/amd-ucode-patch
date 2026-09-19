#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests for the header-data section (the header tail, offsets 10-31).

There is one model per patch format. The registry tests pin which formats are
modelled and that the rest refuse; the rest of the file is one decode test and
one corpus cross-check per field of the ``0x8000`` model.
"""

import collections
import struct
import warnings
from pathlib import Path

import pytest

from amd_cpuid import AmdCpuId

from amd_ucode_patch.structures.header_data import HeaderData
from amd_ucode_patch.structures.header_data_default import HeaderDataDefault
from amd_ucode_patch.structures.header_data_fam0fto12 import (
    HeaderDataFam0fto12,
)
from amd_ucode_patch.structures.header_data_fam14to15 import (
    HeaderDataFam14to15,
)
from amd_ucode_patch.structures.header_data_registry import (
    header_data_class,
    is_modelled,
)
from amd_ucode_patch.structures.patch_level import PatchLevel

from conftest import patch_level_of

#: A 22-byte region with a distinct value in every slot.
_SAMPLE = bytes(range(HeaderData.SIZE))

#: Offset of the header-data region within a patch file.
_DATA_OFF = 10
#: Pre-Zen framing: a 64-byte header region (the 32-byte core plus
#: ``match_reg[8]``) followed by ``op_triad_count`` triads of 3 * u64 + u32.
_HEADER_REGION_SIZE, _TRIAD_SIZE = 64, 28

# -- the framing --

def test_size_is_22():
    assert HeaderDataFam0fto12.SIZE == 22


def test_is_a_header_data():
    assert issubclass(HeaderDataFam0fto12, HeaderData)
    assert isinstance(HeaderDataFam0fto12.from_bytes(_SAMPLE), HeaderData)


def test_roundtrip_exact():
    assert HeaderDataFam0fto12.from_bytes(_SAMPLE).to_bytes() == _SAMPLE


def test_reads_only_its_region():
    assert HeaderDataFam0fto12.from_bytes(_SAMPLE + b"more").to_bytes() == _SAMPLE


def test_rejects_short_buffer():
    with pytest.raises(ValueError):
        HeaderDataFam0fto12.from_bytes(bytes(HeaderData.SIZE - 1))


# -- the registry: keyed on family, with a default fallback --

def _patch_level_for_family(family: int) -> PatchLevel:
    """A patch level whose top byte encodes ``family`` (base 0xF + extended)."""
    return PatchLevel(value=(family - 0xF) << 24)


@pytest.mark.parametrize("family", [0x14, 0x15])
def test_registry_resolves_the_bobcat_bulldozer_families(family):
    """0x14/0x15 have a model of their own, but not the triad one."""
    level = _patch_level_for_family(family)
    assert is_modelled(level)
    assert header_data_class(level) is HeaderDataFam14to15


@pytest.mark.parametrize("family", [0x0F, 0x10, 0x11, 0x12])
def test_registry_resolves_the_triad_families(family):
    """Families 0x0f-0x12 (K8, K10, Griffin, Llano) share the triad format."""
    level = _patch_level_for_family(family)
    assert is_modelled(level)
    assert header_data_class(level) is HeaderDataFam0fto12


@pytest.mark.parametrize("family", [0x16, 0x17, 0x19, 0x1A, 0x99])
def test_registry_falls_back_to_the_default(family):
    """
    A family with no model of its own is neither refused nor guessed at: the
    default model decodes the one field every known format agrees on, and every
    layout covers the same 22 bytes, so the region still round-trips. This is
    where loader id 0x8003's Jaguar (family 0x16) parts land, apart from its
    Llano (family 0x12) parts above.
    """
    level = _patch_level_for_family(family)
    assert not is_modelled(level)
    assert header_data_class(level) is HeaderDataDefault


# -- the default model --

def test_default_is_a_header_data():
    assert issubclass(HeaderDataDefault, HeaderData)
    assert HeaderDataDefault.SIZE == 22


def test_default_roundtrip_exact():
    assert HeaderDataDefault.from_bytes(_SAMPLE).to_bytes() == _SAMPLE


def test_default_rejects_short_buffer():
    with pytest.raises(ValueError):
        HeaderDataDefault.from_bytes(bytes(HeaderData.SIZE - 1))


def test_default_decodes_only_the_cpuid():
    """
    Offsets 10-23 are where the formats disagree, so the default model leaves
    them verbatim and decodes offset 24 alone.
    """
    data = HeaderDataDefault.from_bytes(_SAMPLE)
    assert data.unknown0 == _SAMPLE[0:14]
    assert data.cpuid == AmdCpuId.from_ucode_signature(0x0F0E)
    assert data.unknown1 == _SAMPLE[16:22]


def test_default_decodes_the_same_cpuid_as_a_specific_model(
        modelled_patch_file: Path):
    """
    The default must agree with a format-specific model on the field they both
    decode, or the fallback would report a different processor than the model.
    """
    region = modelled_patch_file.read_bytes()[_DATA_OFF:]
    assert (HeaderDataDefault.from_bytes(region).cpuid
            == HeaderDataFam0fto12.from_bytes(region).cpuid)


def test_default_roundtrips_every_corpus_file(patch_file: Path):
    """The fallback has to hold for formats it was never designed against."""
    region = patch_file.read_bytes()[_DATA_OFF:_DATA_OFF + HeaderData.SIZE]
    assert HeaderDataDefault.from_bytes(region).to_bytes() == region


# -- fields, one at a time --

def _region(**overrides) -> bytes:
    """A 22-byte region with a distinct value in every field."""
    fields = dict(op_triad_count=0x20, init_flag=0x01, op_triad_checksum=0xDEADBEEF,
                  unknown0=bytes(range(0x60, 0x68)),
                  cpuid=AmdCpuId.from_ucode_signature(0x0050),
                  unknown1=bytes(range(0x70, 0x76)))
    return HeaderDataFam0fto12(**{**fields, **overrides}).to_bytes()


def test_every_field_lands_on_its_own_value():
    """Each field decodes to the value it was given, and nothing overlaps."""
    data = HeaderDataFam0fto12.from_bytes(_region())
    assert data.op_triad_count == 0x20
    assert data.init_flag == 0x01
    assert data.op_triad_checksum == 0xDEADBEEF
    assert data.unknown0 == bytes(range(0x60, 0x68))
    assert data.cpuid == AmdCpuId.from_ucode_signature(0x0050)
    assert data.unknown1 == bytes(range(0x70, 0x76))


@pytest.mark.parametrize(("field", "offset", "encoded"), [
    ("op_triad_count", 0, "20"),
    ("init_flag", 1, "01"),
    ("op_triad_checksum", 2, "efbeadde"),
    ("unknown0", 6, "6061626364656667"),
    ("cpuid", 14, "5000"),
    ("unknown1", 16, "707172737475"),
])
def test_field_encoding_and_placement(field, offset, encoded):
    """Every field serializes little-endian at the region offset it claims."""
    raw = bytes.fromhex(encoded)
    assert _region()[offset:offset + len(raw)] == raw


@pytest.mark.parametrize(("field", "value"), [
    ("op_triad_count", 0x10), ("init_flag", 0x00), ("op_triad_checksum", 0x12345678),
    ("unknown0", bytes(8)), ("cpuid", AmdCpuId.from_ucode_signature(0x0210)), ("unknown1", bytes(6)),
])
def test_field_edit_persists(field, value):
    data = HeaderDataFam0fto12.from_bytes(_region())
    setattr(data, field, value)
    assert getattr(HeaderDataFam0fto12.from_bytes(data.to_bytes()), field) == value


# -- corpus cross-checks, one per field --

def _corpus_data(patch_file: Path) -> HeaderDataFam0fto12:
    return HeaderDataFam0fto12.from_bytes(patch_file.read_bytes()[_DATA_OFF:])


def test_cpuid_encoding_survives_every_value():
    """
    The field is stored decoded, so the encoding must be lossless or patches
    would not round-trip: every u16 the region can hold decodes and re-encodes
    to itself.
    """
    assert all(AmdCpuId.from_ucode_signature(v).ucode_signature == v
               for v in range(0x10000))


def test_cpuid_family_agrees_with_patch_level(corpus_dir: Path):
    """
    The cross-check that justifies decoding this field as a CPUID: the family
    it names matches the (corrected) family in ``patch_level``, an independent
    field. Over the triad families they agree except for the one Llano patch
    whose CPUID field is an equivalence id (``0x1200`` -> family 0x10) rather
    than a packed CPUID -- the counterexample from the discriminator study.
    """
    agree = disagree = 0
    for path in sorted(corpus_dir.glob("*.bin")):
        level = patch_level_of(path)
        if header_data_class(level) is not HeaderDataFam0fto12:
            continue
        with warnings.catch_warnings():           # the corrected-family warnings
            warnings.simplefilter("ignore")
            family = level.family
        if _corpus_data(path).cpuid.family == family:
            agree += 1
        else:
            disagree += 1
    assert (agree, disagree) == (42, 1)


def test_op_triad_count_accounts_for_the_file(triad_patch_file: Path):
    """
    The cross-check that proves the decode: the field accounts for the whole
    file as a triad count, on 40/40 corpus patches.
    """
    buf = triad_patch_file.read_bytes()
    data = _corpus_data(triad_patch_file)
    assert len(buf) == _HEADER_REGION_SIZE + _TRIAD_SIZE * data.op_triad_count


def test_init_flag_is_zero_or_one(triad_patch_file: Path):
    """Patent US6438664B1 describes a flag, and the corpus only ever sets it."""
    assert _corpus_data(triad_patch_file).init_flag in (0x00, 0x01)


def test_op_triad_checksum_sums_the_triad_array(triad_patch_file: Path):
    """
    The decode that names the field: it is the u32 sum of exactly the region
    ``op_triad_count`` delimits. Holds 40/40, and no other region sums to it.
    """
    buf = triad_patch_file.read_bytes()
    data = _corpus_data(triad_patch_file)
    triads = buf[_HEADER_REGION_SIZE:
                 _HEADER_REGION_SIZE + _TRIAD_SIZE * data.op_triad_count]
    words = struct.unpack(f"<{len(triads) // 4}I", triads)
    assert sum(words) & 0xFFFFFFFF == data.op_triad_checksum



def test_cpuid_width_is_structural(corpus_dir: Path):
    """
    The evidence for the u16 width at offset 24: two groups of patches share
    this value while the two bytes after it differ. Under zentool's ``u32
    cpuid`` reading those would be distinct parts rather than one part at
    successive revisions.
    """
    by_id = collections.defaultdict(set)
    for path in sorted(corpus_dir.glob("*.bin")):
        if not is_modelled(patch_level_of(path)):
            continue
        data = _corpus_data(path)
        by_id[data.cpuid].add(data.unknown1[:2])
    assert sum(len(tails) > 1 for tails in by_id.values()) == 2






def test_roundtrip_matches_corpus(modelled_patch_file: Path):
    region = modelled_patch_file.read_bytes()[_DATA_OFF:_DATA_OFF + HeaderData.SIZE]
    assert HeaderDataFam0fto12.from_bytes(region).to_bytes() == region
