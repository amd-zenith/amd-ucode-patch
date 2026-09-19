#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests for the canonical patch filename.

The tool always emits an ``_enc<ee>`` component (the body header's flag, or
``00`` without one). The corpus omits it on the older families, so the strongest
check reconstructs each stored name's core and SHA with the normalized ``_enc``
and compares -- verifying the family/CPUID/rev/date/SHA against the corpus while
allowing the always-present ``_enc``.
"""

import re
import struct
from pathlib import Path

import pytest

from amd_ucode_patch.structures.header import Header
from amd_ucode_patch.structures.patch import Patch

#: Splits a stored corpus filename into its parts (``_enc`` optional).
_NAME = re.compile(
    r"(?P<core>family[0-9a-f]+_cpuid[0-9A-F]+_rev[0-9a-f]+_date\d{8})"
    r"(?:_enc(?P<enc>\d{2}))?_sha(?P<sha>[0-9a-f]{12})\.bin"
)


def _synthetic_patch() -> bytes:
    """
    A minimal patch in a modelled, unsigned format (no body header).

    The zero patch level makes it family 0x0f, whose body opens with eight
    match registers, so it carries a body long enough to hold them.
    """
    core = bytearray(Header.CORE_SIZE)
    struct.pack_into("<H", core, 8, 0x8000)
    return bytes(core) + bytes(32)


def _parts(name: str) -> re.Match:
    match = _NAME.match(name)
    assert match, f"unexpected corpus filename: {name}"
    return match


def test_name_always_includes_enc(patch_file: Path):
    """Every name carries an ``_enc`` component, corpus-wide."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    assert re.search(r"_enc\d{2}_sha", patch.name_canonical)


def test_reproduces_the_corpus_core_and_sha(patch_file: Path):
    """
    The core, the ``_enc`` value and the SHA match the stored name. The stored
    name may omit ``_enc`` (older families); the expected name always includes
    it, defaulting to ``00``.

    The family component follows the patch level, which is authoritative and can
    disagree with the equivalence-id family the collection used to name a few
    pre-Zen files; the stored core's family is normalized to it before comparing.
    """
    patch = Patch.from_bytes(patch_file.read_bytes())
    parts = _parts(patch_file.name)
    body_header = patch.body.body_header
    enc = body_header.encrypted if body_header is not None else 0
    core = re.sub(r"^family[0-9a-f]+",
                  f"family{patch.header.patch_level.family:02x}", parts["core"])
    expected = f"{core}_enc{enc:02}_sha{parts['sha']}.bin"
    assert patch.name_canonical == expected


def test_family_follows_the_patch_level_not_the_equivalence_id(corpus_dir: Path):
    """
    A few pre-Zen files carry a CPUID equivalence id whose family disagrees with
    the (authoritative) patch level -- the Llano ``0x1200`` id reads as family
    0x10. The canonical name must follow the patch level, not the id.
    """
    relabelled = 0
    for path in sorted(corpus_dir.glob("*.bin")):
        patch = Patch.from_bytes(path.read_bytes())
        pl_family = patch.header.patch_level.family
        if pl_family == patch.header.data.cpuid.family:
            continue
        relabelled += 1
        assert patch.name_canonical.startswith(f"family{pl_family:02x}_")
    assert relabelled >= 1, "expected at least the Llano 0x1200 patch"


def test_enc_comes_from_the_body_header(patch_file: Path):
    """Where a body header exists, ``_enc`` is exactly its flag."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.body.body_header is None:
        pytest.skip("patch has no body header")
    enc = patch.body.body_header.encrypted
    assert f"_enc{enc:02}_" in patch.name_canonical


def test_enc_defaults_to_00_without_a_body_header(patch_file: Path):
    patch = Patch.from_bytes(patch_file.read_bytes())
    if patch.body.body_header is not None:
        pytest.skip("patch has a body header")
    assert "_enc00_" in patch.name_canonical


def test_synthetic_patch_gets_enc00():
    patch = Patch.from_bytes(_synthetic_patch())
    assert patch.body.body_header is None
    assert "_enc00_" in patch.name_canonical


def test_name_ends_with_the_patch_sha(patch_file: Path):
    patch = Patch.from_bytes(patch_file.read_bytes())
    assert patch.name_canonical.endswith(f"_sha{patch.sha256[:12]}.bin")


def test_name_reflects_an_edit(patch_file: Path):
    """A changed patch gets a changed name, because the SHA covers the whole."""
    patch = Patch.from_bytes(patch_file.read_bytes())
    before = patch.name_canonical
    patch.header.date.year += 1
    assert patch.name_canonical != before
