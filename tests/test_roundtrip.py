#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The round-trip spine.

``Patch.from_bytes(b).to_bytes() == b`` for every patch in the corpus. This is
the invariant the rewrite must never break: as sections are carved out of the
raw buffer, the reconstruction must stay byte-exact, because ``resign`` rewrites
files in place. Every step of the refactor is gated on this test staying green.

It covers the whole corpus, including the formats with no header-data model of
their own: those fall back to the default model, which decodes one field and
keeps the rest verbatim, so they round-trip too.
"""

from pathlib import Path

from amd_ucode_patch.structures.patch import Patch


def test_roundtrip(patch_file: Path):
    original = patch_file.read_bytes()
    assert Patch.from_bytes(original).to_bytes() == original
