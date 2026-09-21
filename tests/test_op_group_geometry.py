#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests for the microcode operation-group geometry.

Only the families whose own format settles the layout are recorded, so the
table is small and every entry is fully decomposed.
"""

import pytest

from amd_ucode_patch.structures.op_group_geometry import OpGroupGeometry


# -- the type --

def test_group_size_follows_from_the_breakdown():
    g = OpGroupGeometry(op_size=8, ops_per_group=3, sequence_word_size=4)
    assert g.group_size == 28


def test_counting_groups():
    g = OpGroupGeometry(op_size=8, ops_per_group=3, sequence_word_size=4)
    assert g.group_count(28 * 5) == 5
    assert g.holds_whole_groups(28 * 5)
    assert g.group_count(28 * 5 + 3) == 5        # floor: the whole ones
    assert not g.holds_whole_groups(28 * 5 + 3)
    assert g.group_count(0) == 0
    assert g.holds_whole_groups(0)


def test_geometry_is_immutable():
    g = OpGroupGeometry(op_size=8, ops_per_group=3, sequence_word_size=4)
    with pytest.raises(Exception):
        g.op_size = 4


# -- what each family uses --

@pytest.mark.parametrize("family", [0x0F, 0x10, 0x11, 0x12])
def test_the_triad_families_share_one_geometry(family):
    g = OpGroupGeometry.for_family(family)
    assert (g.op_size, g.ops_per_group, g.sequence_word_size) == (8, 3, 4)
    assert g.group_size == 28


@pytest.mark.parametrize("family", [0x17, 0x19])
def test_the_quad_families_share_one_geometry(family):
    g = OpGroupGeometry.for_family(family)
    assert (g.op_size, g.ops_per_group, g.sequence_word_size) == (8, 4, 4)
    assert g.group_size == 36


@pytest.mark.parametrize("family", [0x14, 0x15, 0x16, 0x1A, 0x99])
def test_no_geometry_where_the_format_does_not_settle_one(family):
    """
    A group size read off repeating filler is not the same as a layout the
    format settles. These families offer neither a count over the array nor an
    idle op that pins the alignment, so they are not recorded.
    """
    assert OpGroupGeometry.for_family(family) is None


def test_the_two_recorded_geometries_are_distinct():
    """A quad is a triad plus one more op, so the group sizes differ by 8."""
    triad = OpGroupGeometry.for_family(0x0F)
    quad = OpGroupGeometry.for_family(0x19)
    assert quad.group_size - triad.group_size == triad.op_size
