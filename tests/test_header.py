#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests for the :class:`Header` section."""

import json
import re
import struct
from pathlib import Path

import pytest

from amd_ucode_patch.structures.patch import Patch
from amd_ucode_patch.structures.date import Date
from amd_ucode_patch.structures.header import Header
from amd_ucode_patch.structures.header_data import HeaderData
from amd_ucode_patch.structures.loader_id import LoaderId
from amd_ucode_patch.structures.patch_level import PatchLevel
from amd_ucode_patch.structures.signature_fam17plus import SignatureFam17Plus

_BASELINE = json.loads((Path(__file__).parent / "data" / "baseline.json").read_text())

#: Offset of the loader id in the core, and a modelled format to put there.
#: A synthetic core needs one: an unmodelled format refuses to parse.
_LOADER_ID_OFF, _MODELLED_LOADER_ID = 8, 0x8000


def _core(raw: bytes = b"") -> bytes:
    """A 32-byte core carrying ``raw``, forced to a modelled, opaque format."""
    core = bytearray(raw.ljust(Header.CORE_SIZE, bytes(1))[:Header.CORE_SIZE])
    struct.pack_into("<H", core, _LOADER_ID_OFF, _MODELLED_LOADER_ID)
    # Force patch level family 0x14 (Bobcat): no signature slot, so a minimal
    # core needs no trailing block to parse.
    struct.pack_into("<I", core, 4, 0x05000000)
    return bytes(core)


def test_core_size_is_32():
    assert Header.CORE_SIZE == 32


def test_unsigned_core_roundtrips():
    raw = _core(bytes(range(Header.CORE_SIZE)))
    header = Header.from_bytes(raw)
    assert header.signature is None
    assert header.size == Header.CORE_SIZE
    assert header.to_bytes() == raw


def test_from_bytes_reads_only_the_core_when_unsigned():
    raw = _core(bytes(range(Header.CORE_SIZE))) + b"trailing"
    assert Header.from_bytes(raw).to_bytes() == raw[:Header.CORE_SIZE]


def test_fields_decoded():
    raw = bytearray(Header.CORE_SIZE)
    raw[0:4] = bytes.fromhex("07201406")   # date 2007-06-14
    raw[4:8] = bytes.fromhex("08000002")   # patch_level 0x02000008
    struct.pack_into("<H", raw, 8, 0x8000)  # loader_id (unsigned format)
    header = Header.from_bytes(bytes(raw))
    assert isinstance(header.date, Date) and str(header.date) == "2007-06-14"
    assert isinstance(header.patch_level, PatchLevel) and header.patch_level.value == 0x02000008
    assert isinstance(header.loader_id, LoaderId) and header.loader_id.value == 0x8000
    assert isinstance(header.data, HeaderData)
    assert header.signature is None


def test_rejects_short_buffer():
    with pytest.raises(ValueError):
        Header.from_bytes(b"\x00" * (Header.CORE_SIZE - 1))


# -- edits persist through to_bytes, including nested fields --

def test_edit_loader_id_persists():
    header = Header.from_bytes(_core())
    header.loader_id.value = 0x8005
    assert struct.unpack_from("<H", header.to_bytes(), 8)[0] == 0x8005


def test_edit_nested_date_field_persists():
    header = Header.from_bytes(_core(bytes.fromhex("07201406")))
    header.date.year = 2021
    assert header.to_bytes()[0:4] == Date(year=2021, month=6, day=14).to_bytes()


def test_edit_nested_patch_level_persists():
    header = Header.from_bytes(_core())
    header.patch_level.value = 0x0A000033
    assert header.to_bytes()[4:8] == bytes.fromhex("3300000a")


def test_edit_persists_through_patch():
    # The edit moves the patch to family 0x10, whose body opens with eight
    # match registers, so the body has to be long enough to hold them on the
    # way back in.
    body = bytes(range(32))
    patch = Patch.from_bytes(_core(bytes.fromhex("07201406")) + body)
    patch.header.date.day = 28
    patch.header.patch_level.value = 0x0100008F
    rebuilt = Patch.from_bytes(patch.to_bytes())
    assert rebuilt.header.date.day == 28
    assert rebuilt.header.patch_level.value == 0x0100008F
    assert rebuilt.body.to_bytes() == body


# -- corpus-backed --

def test_loader_id_matches_corpus(modelled_patch_file: Path):
    buf = modelled_patch_file.read_bytes()
    assert Patch.from_bytes(buf).header.loader_id.value == struct.unpack_from("<H", buf, 8)[0]


def test_header_data_roundtrips_corpus(modelled_patch_file: Path):
    buf = modelled_patch_file.read_bytes()
    assert Patch.from_bytes(buf).header.data.to_bytes() == buf[10:32]


def test_header_roundtrips_corpus(modelled_patch_file: Path):
    buf = modelled_patch_file.read_bytes()
    header = Patch.from_bytes(buf).header
    assert header.to_bytes() == buf[:header.size]


def test_signature_presence_matches_corpus(patch_file: Path):
    """
    The baseline ``signed`` flag is the key-free RSA structural test, so it
    picks out exactly the RSA (family 0x17+) block -- not family 0x16, which
    carries a non-RSA signature slot.
    """
    header = Patch.from_bytes(patch_file.read_bytes()).header
    rsa_signed = _BASELINE[patch_file.name]["signed"]
    assert isinstance(header.signature, SignatureFam17Plus) == rsa_signed
    if rsa_signed:
        assert header.size == Header.CORE_SIZE + SignatureFam17Plus.SIZE


def test_date_matches_corpus_filename(modelled_patch_file: Path):
    match = re.search(r"_date(\d{8})_", modelled_patch_file.name)
    assert match, f"no date in filename {modelled_patch_file.name}"
    decoded = str(
        Patch.from_bytes(modelled_patch_file.read_bytes()).header.date
    ).replace("-", "")
    assert decoded == match.group(1)


def test_patch_level_matches_corpus_filename(modelled_patch_file: Path):
    match = re.search(r"_rev([0-9a-fA-F]{8})_", modelled_patch_file.name)
    assert match, f"no rev in filename {modelled_patch_file.name}"
    decoded = str(
        Patch.from_bytes(modelled_patch_file.read_bytes()).header.patch_level)
    assert decoded == match.group(1).lower()
