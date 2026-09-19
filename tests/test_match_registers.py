#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests for the match-register array a microcode body opens with.

The array is assumed 32-bit for now and carries its own count, plus the
knowledge of how many registers each family opens its body with. These pin the
framing, the unused-slot marker, and which families claim a count.
"""

import struct

import pytest

from amd_ucode_patch.structures.match_registers import MatchRegisters

#: How many registers families 0x0f-0x11 carry.
_COUNT = 8
#: The families whose body opens with match registers, and one of them.
_MATCH_FAMILIES = (0x0F, 0x10, 0x11)
_MATCH_FAMILY = 0x10
#: A family whose body does not.
_OTHER_FAMILY = 0x14


def _array(values: list[int]) -> bytes:
    return struct.pack(f"<{len(values)}I", *values)


# -- the framing --

def test_registers_are_32_bit():
    assert MatchRegisters.REGISTER_SIZE == 4
    assert MatchRegisters(values=[0] * 3).size == 12


def test_parses_the_declared_count():
    registers = MatchRegisters.from_bytes(_array(list(range(_COUNT))), _COUNT)
    assert registers.values == list(range(_COUNT))
    assert registers.count == _COUNT
    assert registers.size == _COUNT * MatchRegisters.REGISTER_SIZE


def test_roundtrip_exact():
    raw = _array([0xDEADBEEF, 0, 0xFFFFFFFF, 1, 2, 3, 4, 5])
    assert MatchRegisters.from_bytes(raw, _COUNT).to_bytes() == raw


def test_reads_only_its_own_array():
    raw = _array(list(range(_COUNT)))
    assert MatchRegisters.from_bytes(raw + b"microcode", _COUNT).to_bytes() == raw


def test_rejects_a_short_buffer():
    with pytest.raises(ValueError):
        MatchRegisters.from_bytes(_array([1, 2]), _COUNT)


def test_a_buffer_that_exactly_fits_is_accepted():
    raw = _array(list(range(_COUNT)))
    assert MatchRegisters.from_bytes(raw, _COUNT).to_bytes() == raw


def test_edit_persists():
    registers = MatchRegisters.from_bytes(_array([0] * _COUNT), _COUNT)
    registers.values[0] = 0xCAFEBABE
    assert MatchRegisters.from_bytes(registers.to_bytes(), _COUNT).values[0] == 0xCAFEBABE


# -- the unused slots --

def test_unused_value_is_all_ones():
    assert MatchRegisters(values=[]).unused_value == 0xFFFFFFFF


def test_used_drops_the_unused_slots():
    raw = _array([0x644, 0xFFFFFFFF, 0x6A4, 0xFFFFFFFF, 0x972, 0x970, 0xB9B, 0xFFFFFFFF])
    registers = MatchRegisters.from_bytes(raw, _COUNT)
    assert registers.used == [0x644, 0x6A4, 0x972, 0x970, 0xB9B]
    assert registers.count == _COUNT


def test_a_fully_unused_array_has_no_used_registers():
    registers = MatchRegisters.from_bytes(_array([0xFFFFFFFF] * _COUNT), _COUNT)
    assert registers.used == []
    assert registers.count == _COUNT


# -- which families carry them: the array's own knowledge --

@pytest.mark.parametrize("family", _MATCH_FAMILIES)
def test_count_is_claimed_for_the_proven_families(family):
    assert MatchRegisters.count_for_family(family) == _COUNT


@pytest.mark.parametrize("family", [0x12, 0x14, 0x15, 0x16, 0x17, 0x19, 0x1A])
def test_no_count_is_claimed_for_any_other_family(family):
    assert MatchRegisters.count_for_family(family) == 0


def test_for_family_parses_the_families_that_carry_them():
    raw = _array(list(range(_COUNT))) + b"microcode"
    registers = MatchRegisters.for_family(raw, _MATCH_FAMILY)
    assert registers.values == list(range(_COUNT))
    assert registers.size == 32


def test_for_family_is_none_when_the_family_carries_none():
    """``None``, not an empty array: the format is not modelled that far."""
    assert MatchRegisters.for_family(_array([1] * _COUNT), _OTHER_FAMILY) is None


def test_for_family_refuses_a_short_buffer():
    with pytest.raises(ValueError):
        MatchRegisters.for_family(b"short", _MATCH_FAMILY)


def test_for_family_accepts_any_length_when_no_count_is_claimed():
    """Only a declared count can be unmet, so these families never refuse."""
    assert MatchRegisters.for_family(b"", _OTHER_FAMILY) is None
