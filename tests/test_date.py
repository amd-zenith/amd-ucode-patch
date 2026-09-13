#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests for the :class:`Date` field."""

from pathlib import Path

import pytest

from amd_ucode_patch.structures.date import Date

# Bytes 07 20 14 06 => year 0x2007, day 0x14, month 0x06 => 2007-06-14.
_SAMPLE = bytes.fromhex("07201406")


def test_size_is_4():
    assert Date.SIZE == 4


def test_from_bytes_decodes_fields():
    date = Date.from_bytes(_SAMPLE)
    assert (date.year, date.month, date.day) == (2007, 6, 14)


def test_roundtrip_exact():
    assert Date.from_bytes(_SAMPLE).to_bytes() == _SAMPLE


def test_construct_and_serialize():
    assert Date(year=2007, month=6, day=14).to_bytes() == _SAMPLE


def test_fields_are_editable():
    date = Date.from_bytes(_SAMPLE)
    date.year = 2021
    date.month = 12
    date.day = 28
    # year 0x2021 (LE) + day 0x28 + month 0x12.
    assert date.to_bytes() == bytes.fromhex("21202812")
    assert Date.from_bytes(date.to_bytes()) == Date(year=2021, month=12, day=28)


def test_str():
    assert str(Date.from_bytes(_SAMPLE)) == "2007-06-14"


def test_from_bytes_reads_only_the_word():
    assert Date.from_bytes(_SAMPLE + b"more").to_bytes() == _SAMPLE


def test_rejects_short_buffer():
    with pytest.raises(ValueError):
        Date.from_bytes(b"\x00\x00\x00")


def test_roundtrip_matches_corpus(patch_file: Path):
    word = patch_file.read_bytes()[:Date.SIZE]
    assert Date.from_bytes(word).to_bytes() == word
