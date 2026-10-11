#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Cross-check the pre-Zen triad deobfuscator against the Ghidra implementation.

The sibling ``GhidraAmdMicrocode`` project carries an independent, separately
tested port of the same transform in
``src/main/java/ghidraamdmicrocode/disasm/PreZenTriadCodec.java``
(``deobfuscate(byte[] body, int triadCount)``). Two implementations of one spec
agreeing on the same bytes is stronger evidence than either alone, so this module
checks ours against it two ways:

* against the exact vectors the Ghidra codec's own unit test pins itself to
  (``PreZenTriadCodecTest.REFERENCE_VECTORS``), which that test documents as
  ``OpGroup(*deobfuscate_triad(raw, index)).to_bytes()`` from this parser; and
* over the whole corpus, against a faithful transcription of the Java
  ``deobfuscate`` here -- structured as the Java is (whole body at once,
  join-then-invert on a byte array), unlike our per-triad, invert-then-join path
  -- so agreement is not a tautology.

The Ghidra codec emits the decoded triad little-endian: three u64 micro-ops then
the u32 sequence word. That is exactly what :meth:`OpGroup.to_bytes` produces, so
it is the common representation both sides are compared in.
"""

from pathlib import Path

import pytest

from amd_ucode_patch.structures.body_data_fam0fto12 import BodyDataFam0fto12
from amd_ucode_patch.structures.op_group import OpGroup
from amd_ucode_patch.structures.patch import Patch
from amd_ucode_patch.utils.triad_obfuscation import TRIAD_SIZE, deobfuscate_triad

_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF
_WORDS_PER_TRIAD = 7
_PRE_ZEN_FAMILIES = (0x0F, 0x10, 0x11, 0x12)

#: Vectors copied verbatim from the Ghidra codec's own unit test,
#: ``GhidraAmdMicrocode/src/test/java/ghidraamdmicrocode/disasm/PreZenTriadCodecTest.java``
#: (``REFERENCE_VECTORS``): ``(raw triad hex, triad index, decoded triad hex)``.
#: The decoded form is the little-endian three-op-plus-sequence-word layout, i.e.
#: ``OpGroup(*deobfuscate_triad(raw, index)).to_bytes()``.
_REFERENCE_VECTORS = [
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b", 0,
     "fffefdfc7dfd7cfcbd7d3dfd5e3e1e7eeedecefe574f475f9b97939f"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b", 1,
     "fdfbf9fffaf9f8fbfb7afa7b7c3cfcbcbd9dfddd9e8ebeae2f273f37"),
    ("0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2", 5,
     "fe59b590b663110f3e15ec624cb827e3ffb46a48ebc6a1102b9906be"),
    ("fff6ede4dbd2c9c0b7aea59c938a81786f665d544b423930271e150c", 31,
     "0d8004890f498bcd0c294a6bc856e77785cc145dd3f61a3fb1c3d5e7"),
]


def _decoded_bytes(raw: bytes, index: int) -> bytes:
    """Our deobfuscation of one triad, in the Ghidra codec's byte layout."""
    return OpGroup(*deobfuscate_triad(raw, index)).to_bytes()


# -- against the Ghidra codec's own pinned vectors --

@pytest.mark.parametrize("raw_hex, index, expected_hex", _REFERENCE_VECTORS)
def test_matches_ghidra_reference_vectors(raw_hex, index, expected_hex):
    """Our decoder reproduces, byte for byte, the vectors the Java test pins to."""
    assert _decoded_bytes(bytes.fromhex(raw_hex), index) == bytes.fromhex(expected_hex)


def test_stored_triads_are_bit_inverted():
    """
    The Java ``storedTriadsAreBitInverted`` case: rotation and the pair swap
    leave an all-zero triad unchanged, so an on-disk zero triad decodes to all
    ones.
    """
    assert _decoded_bytes(bytes(TRIAD_SIZE), 0) == b"\xff" * TRIAD_SIZE


def test_index_keys_the_transform():
    """The Java ``theIndexKeysTheTransform`` case: the same triad differs by index."""
    raw = bytes.fromhex(_REFERENCE_VECTORS[0][0])
    assert _decoded_bytes(raw, 0) != _decoded_bytes(raw, 1)


# -- a faithful transcription of the Java codec, for the whole-body check --

def _ror32(value: int, count: int) -> int:
    count &= 31
    return ((value >> count) | (value << (32 - count))) & _MASK32


def _ghidra_deobfuscate(body: bytes, triad_count: int) -> bytes:
    """
    A line-for-line transcription of ``PreZenTriadCodec.deobfuscate``: decode
    ``triad_count`` whole triads from ``body`` and copy any trailing bytes
    through unchanged, returning a buffer the same length as ``body``.
    """
    out = bytearray(len(body))
    for t in range(triad_count):
        base = t * TRIAD_SIZE
        w = [
            _ror32(int.from_bytes(body[base + k * 4:base + k * 4 + 4], "little"),
                   t * _WORDS_PER_TRIAD + k)
            for k in range(_WORDS_PER_TRIAD)
        ]
        w[0], w[1] = w[1], w[0]
        w[2], w[3] = w[3], w[2]
        w[4], w[5] = w[5], w[4]
        out[base:base + 8] = (~((w[0] << 32) | w[1]) & _MASK64).to_bytes(8, "little")
        out[base + 8:base + 16] = (~((w[2] << 32) | w[3]) & _MASK64).to_bytes(8, "little")
        out[base + 16:base + 24] = (~((w[4] << 32) | w[5]) & _MASK64).to_bytes(8, "little")
        out[base + 24:base + 28] = (~w[6] & _MASK32).to_bytes(4, "little")
    consumed = triad_count * TRIAD_SIZE
    if consumed < len(body):
        out[consumed:] = body[consumed:]
    return bytes(out)


def test_transcription_matches_our_decoder_on_the_reference_vectors():
    """
    Guard the transcription itself against the same pinned vectors, so a later
    corpus agreement cannot be an artefact of a transcription bug that happens to
    match our own decoder.
    """
    for raw_hex, index, expected_hex in _REFERENCE_VECTORS:
        body = bytearray((index + 1) * TRIAD_SIZE)
        body[index * TRIAD_SIZE:(index + 1) * TRIAD_SIZE] = bytes.fromhex(raw_hex)
        decoded = _ghidra_deobfuscate(bytes(body), index + 1)
        assert decoded[index * TRIAD_SIZE:(index + 1) * TRIAD_SIZE] == bytes.fromhex(expected_hex)


# -- whole-body parity over the corpus --

def test_whole_body_matches_the_ghidra_codec(patch_file: Path):
    """
    For every pre-Zen patch, the Java codec's whole-body output equals our op
    groups serialized little-endian followed by any trailing partial-triad bytes.
    This runs both implementations over the same real bytes.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.header.patch_level.family not in _PRE_ZEN_FAMILIES:
        pytest.skip("not a pre-Zen triad family")
    body_data = patch.body.body_data
    assert isinstance(body_data, BodyDataFam0fto12)

    raw = body_data.op_triads
    count = body_data.op_triad_count
    theirs = _ghidra_deobfuscate(raw, count)

    ours = b"".join(g.to_bytes() for g in body_data.op_groups)
    ours += raw[count * TRIAD_SIZE:]  # trailing bytes the codec copies verbatim

    assert len(theirs) == len(raw)
    assert ours == theirs
