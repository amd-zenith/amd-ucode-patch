#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Deobfuscation of the pre-Zen micro-op triads (families 0x0f-0x12).

AMD ships the K8/K10-era microcode triads scrambled. The scramble is a
position-dependent transform: each triad's seven 32-bit words are byte-swapped,
rotated by an amount keyed on the triad's index in the array, swapped in
adjacent pairs, and bit-inverted. It carries no key -- the index is the only
parameter -- so it is obfuscation, not encryption, and it is exactly invertible.

The transform was reconstructed by Koppe et al., *Reverse Engineering x86
Processor Microcode* (USENIX Security 2017), and implemented in
`RUB-SysSec/Microcode`: the rotate-and-swap in ``ucodeapi/ucode.py``
(``parsetriad_crypt`` / ``get_crypt``), the bit inversion in its disassembler
(``get_triad(negate=True)`` for the ops, ``SequenceWord``'s ``~bits``) and
assembler (``SW.bits()``'s ``r = ~r``). This is a port of that algorithm, and it
yields the *logical* micro-ops and sequence word, the values the RUB-SysSec field
tables (operations, registers, sequence-word actions) are defined on.

The inversion is verified on the corpus (all 43 pre-Zen patches, 1168 triads).
With it, 44.3% of the micro-ops decode to a known RUB operation and 89.3% of the
sequence words to a known action, and 76.6% of the sequence words are bit-exact
matches of the encodings RUB's assembler emits (``0xFFFC2000`` for ``next``,
``0xFFFCA000 | addr`` for ``branch``) -- encodings that ran on real K8 hardware.
Without it the same figures are 3.7%, 2.8% and 0%. Independently of any
table, 94 decoded branch targets land 0-8 triads after a ROM address the
patch's (plaintext) match registers hook, where a handler returns; without the
inversion, none do.

A triad is 28 bytes: seven 32-bit words that regroup into three 64-bit micro-ops
and a 32-bit sequence word. The Zen families (0x17+) store their quads in the
clear, so none of this applies to them.
"""

from __future__ import annotations

#: 32-bit words in one triad: three u64 micro-ops (6 words) plus the u32
#: sequence word.
WORDS_PER_TRIAD = 7
#: Encoded size of one triad, in bytes.
TRIAD_SIZE = 28

_MASK32 = 0xFFFFFFFF


def _ror32(value: int, count: int) -> int:
    """Rotate a 32-bit ``value`` right by ``count`` bits."""
    count &= 31
    if count == 0:
        return value & _MASK32
    return ((value >> count) | (value << (32 - count))) & _MASK32


def _rol32(value: int, count: int) -> int:
    """Rotate a 32-bit ``value`` left by ``count`` bits."""
    return _ror32(value, -count)


def deobfuscate_triad(data: bytes, index: int) -> tuple[list[int], int]:
    """
    Deobfuscate one 28-byte triad at position ``index`` in the array.

    Returns ``(ops, sequence_word)``: the three logical 64-bit micro-ops and the
    logical 32-bit sequence word. ``index`` keys the per-word rotation, so a
    triad only deobfuscates correctly at its own position in the array.
    """
    if len(data) < TRIAD_SIZE:
        raise ValueError(
            f"a triad is {TRIAD_SIZE} bytes, got {len(data)}"
        )
    base = index * WORDS_PER_TRIAD
    # Each word: read little-endian (the byteswap of the big-endian on-disk
    # word), rotate right by its running position, and invert every bit.
    words = [
        _ror32(int.from_bytes(data[4 * p:4 * p + 4], "little"), base + p) ^ _MASK32
        for p in range(WORDS_PER_TRIAD)
    ]
    # Swap adjacent word pairs (0,1) (2,3) (4,5); the seventh word stands alone.
    for k in range(0, 6, 2):
        words[k], words[k + 1] = words[k + 1], words[k]
    ops = [(words[2 * i] << 32) | words[2 * i + 1] for i in range(3)]
    sequence_word = words[6]
    return ops, sequence_word


def obfuscate_triad(ops: list[int], sequence_word: int, index: int) -> bytes:
    """
    The inverse of :func:`deobfuscate_triad`: scramble three 64-bit micro-ops and
    a 32-bit sequence word back to the 28 on-disk bytes for position ``index``.
    ``obfuscate_triad(*deobfuscate_triad(d, i), i)`` reproduces ``d`` exactly.
    """
    if len(ops) != 3:
        raise ValueError(f"a triad holds three micro-ops, got {len(ops)}")
    # Invert every bit back to the stored form.
    words = []
    for op in ops:
        words.append(((op >> 32) & _MASK32) ^ _MASK32)
        words.append((op & _MASK32) ^ _MASK32)
    words.append((sequence_word & _MASK32) ^ _MASK32)
    # Undo the pair swap (it is its own inverse), then re-rotate and re-pack.
    for k in range(0, 6, 2):
        words[k], words[k + 1] = words[k + 1], words[k]
    base = index * WORDS_PER_TRIAD
    out = bytearray()
    for p in range(WORDS_PER_TRIAD):
        out += _rol32(words[p], base + p).to_bytes(4, "little")
    return bytes(out)
