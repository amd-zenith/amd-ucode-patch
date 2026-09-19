#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests for the :class:`PatchLevel` field."""

import struct
from pathlib import Path

import pytest
from amd_cpuid import AmdCpuId

from amd_ucode_patch.structures.patch import Patch
from amd_ucode_patch.structures.patch_level import PatchLevel

# Little-endian bytes 08 00 00 02 => u32 0x02000008.
_SAMPLE = bytes.fromhex("08000002")
_VALUE = 0x02000008


def test_size_is_4():
    assert PatchLevel.SIZE == 4


def test_from_bytes_decodes_value():
    assert PatchLevel.from_bytes(_SAMPLE).value == _VALUE


def test_roundtrip_exact():
    assert PatchLevel.from_bytes(_SAMPLE).to_bytes() == _SAMPLE


def test_construct_and_serialize():
    assert PatchLevel(value=_VALUE).to_bytes() == _SAMPLE


def test_value_is_editable():
    level = PatchLevel.from_bytes(_SAMPLE)
    level.value = 0x0A000033
    assert level.to_bytes() == bytes.fromhex("3300000a")
    assert PatchLevel.from_bytes(level.to_bytes()).value == 0x0A000033


def test_int_and_str():
    level = PatchLevel.from_bytes(_SAMPLE)
    assert int(level) == _VALUE
    assert str(level) == "02000008"


def test_from_bytes_reads_only_the_word():
    assert PatchLevel.from_bytes(_SAMPLE + b"more").to_bytes() == _SAMPLE


def test_rejects_short_buffer():
    with pytest.raises(ValueError):
        PatchLevel.from_bytes(b"\x00\x00\x00")


def test_roundtrip_matches_corpus(patch_file: Path):
    word = patch_file.read_bytes()[4:4 + PatchLevel.SIZE]
    assert PatchLevel.from_bytes(word).to_bytes() == word


# -- the extended family, present in every version --

def test_extended_family_is_the_top_byte():
    assert PatchLevel(value=0x0800126C).extended_family == 0x08
    assert PatchLevel(value=0x02000018).extended_family == 0x02   # Griffin, fam 0x11


def test_family_is_base_plus_extended():
    assert PatchLevel(value=0x0800126C).family == 0x17   # Zen 1
    assert PatchLevel(value=0x0A00121D).family == 0x19   # Zen 3-4
    assert PatchLevel(value=0x00000003).family == 0x0F   # K8


def test_known_anomalies_are_corrected_and_warn():
    """
    The two malformed K8 patch levels correct at the extended-family source, so
    both ``extended_family`` and the derived ``family`` come out right (0x0F).
    """
    for value in (0x02000008, 0xC0012102):
        level = PatchLevel(value=value)
        with pytest.warns(UserWarning, match="malformed"):
            assert level.extended_family == 0x00
        with pytest.warns(UserWarning, match="malformed"):
            assert level.family == 0x0F
        # the on-disk word is untouched; only the interpretation is corrected
        assert level.to_bytes() == value.to_bytes(4, "little")


def test_unknown_family_warns_without_correcting():
    """A family byte that is not real silicon warns but is returned as decoded."""
    level = PatchLevel(value=0x7B000000)          # -> family 0x8A, not real
    with pytest.warns(UserWarning, match="not a known AMD family"):
        assert level.family == 0x8A


def test_is_anomalous_flags_only_the_known_malformed_words():
    """``is_anomalous`` is true for exactly the two corrected K8 words, and it
    does not warn (unlike reading the corrected family)."""
    assert PatchLevel(0x02000008).is_anomalous is True
    assert PatchLevel(0xC0012102).is_anomalous is True
    assert PatchLevel(0x0800002A).is_anomalous is False   # a normal Zen word
    assert PatchLevel(0x00000003).is_anomalous is False   # a normal K8 word


def test_corpus_has_exactly_two_anomalous_patch_levels(corpus_dir: Path):
    """The corpus carries the two known-malformed patch levels and no others."""
    anomalous = sum(
        Patch.from_bytes(p.read_bytes()).header.patch_level.is_anomalous
        for p in sorted(corpus_dir.glob("*.bin"))
    )
    assert anomalous == 2


def test_extended_family_decoded_from_corpus(patch_file: Path):
    word = patch_file.read_bytes()[4:4 + PatchLevel.SIZE]
    level = PatchLevel.from_bytes(word)
    # Away from the two known anomalies, the extended family is the raw top byte
    # and the family is exactly base + extended.
    if level.value not in (0x02000008, 0xC0012102):
        assert level.extended_family == (level.value >> 24) & 0xFF
        assert level.family == 0xF + level.extended_family


def test_family_matches_the_cpuid_field_on_signed(patch_file: Path):
    """
    On Zen the top-byte family must agree with the header's CPUID field, an
    independent word -- 338/338. (Pre-Zen the CPUID field is an equivalence id,
    so the two need not agree, and that is not asserted here.)
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.header.signature is None:
        pytest.skip("unsigned (pre-Zen) patch")
    assert patch.header.patch_level.family == patch.header.data.cpuid.family


# -- the packed CPUID (Jaguar and Zen) --

def test_cpuid_is_none_on_older_families():
    """Pre-Jaguar patch levels carry only a revision counter, so no CPUID."""
    # families 0x0f, 0x10, 0x14, 0x15 -- each is a real corpus revision.
    for value in (0x00000003, 0x01000020, 0x0500000B, 0x06000017):
        assert PatchLevel(value).cpuid is None


def test_cpuid_decodes_zen_model_and_stepping():
    # family 0x17, ucode signature 0x8110: extended model 1, base model 1
    # (model 0x11), stepping 0.
    cpuid = PatchLevel(0x08101004).cpuid
    assert cpuid is not None
    assert cpuid.ucode_signature == 0x8110
    assert (cpuid.family, cpuid.model, cpuid.stepping) == (0x17, 0x11, 0)


def test_cpuid_decodes_base_model_and_stepping():
    # family 0x17, ucode signature 0x8011: base model 1, stepping 1.
    cpuid = PatchLevel(0x08001129).cpuid
    assert cpuid is not None
    assert (cpuid.ucode_signature, cpuid.model, cpuid.stepping) == (0x8011, 1, 1)


def test_cpuid_jaguar_packs_extended_model_in_the_low_nibble():
    # family 0x16 keeps the extended model in byte 2's low nibble: 0x03 here is
    # extended model 3 (model 0x30), where Zen would read 0x30.
    cpuid = PatchLevel(0x07030105).cpuid
    assert cpuid is not None
    assert cpuid.ucode_signature == 0x7301
    assert (cpuid.family, cpuid.model, cpuid.stepping) == (0x16, 0x30, 1)


def test_corpus_packed_cpuid_matches_the_header(patch_file: Path):
    """
    On the families that pack it (0x16/0x17/0x19/0x1a), the CPUID recovered from
    the patch level equals the header's CPUID field -- an independent word.
    Older families expose no packed CPUID.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    packed = patch.header.patch_level.cpuid
    if patch.header.patch_level.family in (0x16, 0x17, 0x19, 0x1A):
        assert packed is not None
        assert packed.ucode_signature == patch.header.data.cpuid.ucode_signature
    else:
        assert packed is None
