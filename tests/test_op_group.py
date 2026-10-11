#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests for the reusable :class:`OpGroup` (micro-op triad/quad)."""

import struct

import pytest

from amd_ucode_patch.structures.op_group import OpGroup


@pytest.mark.parametrize(("op_count", "size"), [(3, 28), (4, 36)])
def test_size(op_count, size):
    assert OpGroup.size(op_count) == size


@pytest.mark.parametrize("op_count", [3, 4])
def test_roundtrip(op_count):
    raw = bytes(range(OpGroup.size(op_count)))
    group = OpGroup.from_bytes(raw, op_count)
    assert len(group.ops) == op_count
    assert group.to_bytes() == raw


def test_fields_decoded():
    raw = struct.pack("<3Q", 1, 2, 3) + struct.pack("<I", 0xABCD)
    group = OpGroup.from_bytes(raw, 3)
    assert group.ops == [1, 2, 3]
    assert group.control == 0xABCD


def test_array_from_bytes():
    raw = bytes(range(OpGroup.size(4))) * 3
    groups = OpGroup.array_from_bytes(raw, 4)
    assert len(groups) == 3
    assert b"".join(g.to_bytes() for g in groups) == raw


def test_array_from_bytes_ignores_a_trailing_partial_group():
    raw = bytes(range(OpGroup.size(4))) * 2 + b"leftover"
    groups = OpGroup.array_from_bytes(raw, 4)
    assert len(groups) == 2


def test_edit_persists():
    group = OpGroup.from_bytes(bytes(OpGroup.size(3)), 3)
    group.ops[0] = 0xDEADBEEFCAFEBABE
    group.control = 0x11223344
    assert OpGroup.from_bytes(group.to_bytes(), 3).ops[0] == 0xDEADBEEFCAFEBABE
