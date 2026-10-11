#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests for the pre-Zen (family 0x0f-0x12) micro-op triad deobfuscator.

The transform is the position-dependent scramble AMD ships K8/K10 triads in,
reconstructed by Koppe et al. (USENIX'17) and RUB-SysSec/Microcode. The
load-bearing property is that it is exactly invertible; the corpus tests add the
evidence that it is the *right* transform, not merely an invertible one.
"""

from pathlib import Path

import pytest

from amd_ucode_patch.structures.patch import Patch
from amd_ucode_patch.structures.triad_obfuscation import (
    TRIAD_SIZE,
    deobfuscate_triad,
    obfuscate_triad,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF
_MASK32 = 0xFFFFFFFF
_PRE_ZEN_FAMILIES = (0x0F, 0x10, 0x11, 0x12)


# -- the transform, hermetically --

def test_triad_size_is_28():
    assert TRIAD_SIZE == 28


@pytest.mark.parametrize("index", [0, 1, 5, 31, 137])
def test_obfuscate_is_the_inverse_of_deobfuscate(index):
    ops = [0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x00112233AABBCCDD]
    sequence_word = 0xDEADBEEF
    raw = obfuscate_triad(ops, sequence_word, index)
    assert len(raw) == TRIAD_SIZE
    got_ops, got_sw = deobfuscate_triad(raw, index)
    assert got_ops == ops
    assert got_sw == sequence_word


@pytest.mark.parametrize("index", [0, 3, 42])
def test_deobfuscate_then_obfuscate_reproduces_the_bytes(index):
    raw = bytes((i * 7 + index) & 0xFF for i in range(TRIAD_SIZE))
    ops, sequence_word = deobfuscate_triad(raw, index)
    assert obfuscate_triad(ops, sequence_word, index) == raw


def test_the_stored_triad_is_bit_inverted():
    """
    Rotation and the pair swap leave an all-zero or all-one triad unchanged, so
    the inversion step alone decides these: zero bytes on disk are logical all
    ones, and logical zeros are stored as all-one bytes.
    """
    assert deobfuscate_triad(bytes(TRIAD_SIZE), 0) == ([_MASK64] * 3, _MASK32)
    assert obfuscate_triad([_MASK64] * 3, _MASK32, 0) == bytes(TRIAD_SIZE)
    assert obfuscate_triad([0, 0, 0], 0, 5) == b"\xff" * TRIAD_SIZE


def test_index_keys_the_transform():
    """A triad decoded at the wrong position gives a different result."""
    raw = bytes(range(TRIAD_SIZE))
    assert deobfuscate_triad(raw, 0) != deobfuscate_triad(raw, 1)


def test_a_short_triad_is_refused():
    with pytest.raises(ValueError):
        deobfuscate_triad(bytes(TRIAD_SIZE - 1), 0)


def test_obfuscate_refuses_the_wrong_op_count():
    with pytest.raises(ValueError):
        obfuscate_triad([1, 2], 0, 0)


# -- corpus-backed: the transform is invertible and yields real structure --

def test_pre_zen_triads_deobfuscate_and_reobfuscate_to_the_original(patch_file: Path):
    """
    Every pre-Zen body's decoded op groups re-scramble back to the exact bytes
    the patch stores -- the invariant the byte-exact round-trip depends on.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.header.patch_level.family not in _PRE_ZEN_FAMILIES:
        pytest.skip("not a pre-Zen triad family")
    body_data = patch.body.body_data
    groups = body_data.op_groups
    assert len(groups) == body_data.op_triad_count
    rebuilt = b"".join(
        obfuscate_triad(g.ops, g.control, i) for i, g in enumerate(groups))
    whole = body_data.op_triads[:len(rebuilt)]
    assert rebuilt == whole
    assert all(0 <= op <= _MASK64 for g in groups for op in g.ops)
    assert all(0 <= g.control <= _MASK32 for g in groups)


def test_deobfuscation_collapses_filler_only_at_the_correct_index(corpus_dir):
    """
    The decisive evidence this is the right transform, not just an invertible
    one. Real microcode is padded with a repeated filler triad; because the
    scramble is keyed on the triad's index, identical filler triads have
    *different* on-disk bytes and only decode back to one and the same op group
    at their correct index. So at the correct index a single decoded group
    dominates a patch, while deobfuscating every triad at a fixed wrong index
    (0) leaves nothing repeated.

    Measured over the corpus: the dominant decoded group reaches ~31% of a
    patch's triads at the correct index, but never more than ~6% at the wrong
    index. This is the calibration §N1 lacked -- it fires only when the
    position-keyed rotation is applied correctly.
    """
    import glob
    from collections import Counter
    from amd_ucode_patch.structures.body_data_fam0fto12 import BodyDataFam0fto12

    correct_shares = []
    wrong_shares = []
    for path in sorted(glob.glob(str(corpus_dir / "*.bin"))):
        try:
            patch = Patch.from_bytes(Path(path).read_bytes())
        except Exception:
            continue
        if patch.header.patch_level.family not in _PRE_ZEN_FAMILIES:
            continue
        body_data = patch.body.body_data
        assert isinstance(body_data, BodyDataFam0fto12)
        raw, step, n = body_data.op_triads, TRIAD_SIZE, body_data.op_triad_count
        if n < 16:
            continue

        def decoded(triad_index, key_index):
            ops, sw = deobfuscate_triad(
                raw[triad_index*step:triad_index*step+step], key_index)
            return tuple(ops), sw

        at_correct = Counter(decoded(i, i) for i in range(n))
        at_wrong = Counter(decoded(i, 0) for i in range(n))
        correct_shares.append(at_correct.most_common(1)[0][1] / n)
        wrong_shares.append(at_wrong.most_common(1)[0][1] / n)

    if not correct_shares:
        pytest.skip("no pre-Zen patches with enough triads in the corpus")
    # A dominant filler emerges only at the correct index; the margin is large.
    assert max(correct_shares) >= 0.20
    assert max(wrong_shares) <= 0.15


#: The sequence words RUB-SysSec's assembler emits (``ucodeas.py`` ``SW.bits()``,
#: before its own ``r = ~r``), which ran on real K8 hardware: ``next`` is one
#: fixed word, ``branch`` a fixed 20-bit prefix ahead of the 12-bit target.
_RUB_NEXT = 0xFFFC2000
_RUB_BRANCH_PREFIX = 0xFFFCA


def test_decoded_sequence_words_are_the_hardware_encoding(corpus_dir):
    """
    The evidence that the bit inversion belongs in the transform. Rotation, swap
    and filler collapse all work the same with or without it (a NOT is a
    bijection), so they cannot tell the two apart; the encoding can. Decoded
    with the inversion, about three quarters of AMD's shipped sequence words
    (76.6% of 1168) are bit-exact matches of what RUB's hardware-tested
    assembler emits for ``next`` and ``branch``; without it, none are.
    """
    import glob
    from amd_ucode_patch.structures.body_data_fam0fto12 import BodyDataFam0fto12

    words = []
    for path in sorted(glob.glob(str(corpus_dir / "*.bin"))):
        try:
            patch = Patch.from_bytes(Path(path).read_bytes())
        except Exception:
            continue
        body_data = patch.body.body_data
        if isinstance(body_data, BodyDataFam0fto12):
            words += [g.control for g in body_data.op_groups]
    if not words:
        pytest.skip("no pre-Zen patches in the corpus")

    def rub_share(ws):
        hits = sum(w == _RUB_NEXT or (w >> 12) == _RUB_BRANCH_PREFIX for w in ws)
        return hits / len(ws)

    assert rub_share(words) >= 0.5
    assert rub_share([w ^ _MASK32 for w in words]) == 0
