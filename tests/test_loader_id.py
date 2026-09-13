#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests for the :class:`LoaderId` field (a plain, uninterpreted value)."""

import pytest

from amd_ucode_patch.structures.loader_id import LoaderId


def test_size_is_2():
    assert LoaderId.SIZE == 2


def test_from_bytes_decodes_value():
    assert LoaderId.from_bytes(bytes.fromhex("0480")).value == 0x8004


def test_roundtrip_exact():
    assert LoaderId.from_bytes(bytes.fromhex("0480")).to_bytes() == bytes.fromhex("0480")


def test_construct_and_serialize():
    assert LoaderId(value=0x8004).to_bytes() == bytes.fromhex("0480")


def test_value_editable():
    lid = LoaderId(value=0x8004)
    lid.value = 0x8005
    assert lid.to_bytes() == bytes.fromhex("0580")


def test_int_and_str():
    lid = LoaderId(value=0x8004)
    assert int(lid) == 0x8004
    assert str(lid) == "8004"


def test_reads_only_the_field():
    assert LoaderId.from_bytes(bytes.fromhex("0480") + b"rest").value == 0x8004


def test_rejects_short_buffer():
    with pytest.raises(ValueError):
        LoaderId.from_bytes(b"\x00")
