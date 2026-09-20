#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Shared pytest fixtures.

The regression tests run against a corpus of real AMD microcode patch files that
is *not* vendored into this repository (it is large and separately licensed). It
lives in a sibling checkout and is located, in order:

1. ``$AMD_UCODE_CORPUS`` if set, or
2. ``../amd-ucode-collection/patches`` next to this repository.

Signature verification additionally needs an AES-CMAC key, which this project
does not ship. Set ``$AMD_UCODE_CMAC_KEY`` to one as 32 hex characters to run
the tests that check a signature against the body it covers; without it those
tests skip and the key-free checks still run.

When no corpus is found the corpus-backed tests skip rather than fail, so the
suite is still green in CI (which does not have the corpus) while giving full
coverage locally. Any test that takes a ``patch_file`` argument is automatically
parametrized over every ``*.bin`` in the corpus.
"""

import os
from pathlib import Path

import pytest

from amd_ucode_patch.structures.header_data_fam0fto12 import HeaderDataFam0fto12
from amd_ucode_patch.structures.header_data_registry import (
    header_data_class,
    is_modelled,
)
from amd_ucode_patch.structures.patch_level import PatchLevel

_REPO_ROOT = Path(__file__).resolve().parent.parent

#: Offset of the patch level in a patch file.
_PATCH_LEVEL_OFF = 4


def _corpus_dir() -> Path:
    env = os.environ.get("AMD_UCODE_CORPUS")
    if env:
        return Path(env)
    return _REPO_ROOT.parent / "amd-ucode-collection" / "patches"


def _corpus_files() -> list[Path]:
    d = _corpus_dir()
    return sorted(d.glob("*.bin")) if d.is_dir() else []


def patch_level_of(patch_file: Path) -> PatchLevel:
    """The patch level of a corpus file, read straight from offset 4."""
    return PatchLevel.from_bytes(patch_file.read_bytes()[_PATCH_LEVEL_OFF:])


@pytest.fixture
def modelled_patch_file(patch_file: Path) -> Path:
    """
    A corpus file whose family has a header-data model of its own.

    Every corpus file parses -- a family with no model of its own falls back to
    the default one -- so this fixture exists for the tests that assert
    format-specific fields. ``test_roundtrip`` covers the whole corpus either
    way, and files join this set as their family lands.
    """
    if not is_modelled(patch_level_of(patch_file)):
        pytest.skip("family has no header-data model of its own")
    return patch_file


@pytest.fixture
def triad_patch_file(patch_file: Path) -> Path:
    """
    A corpus file whose family uses the micro-op triad header-data model.

    Narrower than :func:`modelled_patch_file`: a family can have a model of its
    own without having triads -- Bobcat and Bulldozer (0x14, 0x15) do -- so the
    tests that assert triad fields key on the model, not on being modelled.
    """
    if header_data_class(patch_level_of(patch_file)) is not HeaderDataFam0fto12:
        pytest.skip("family does not use the triad header-data model")
    return patch_file


@pytest.fixture(scope="session")
def corpus_dir() -> Path:
    d = _corpus_dir()
    if not d.is_dir():
        pytest.skip(f"AMD ucode corpus not found at {d} (set AMD_UCODE_CORPUS)")
    return d


def pytest_generate_tests(metafunc):
    """Parametrize any test requesting ``patch_file`` over the whole corpus."""
    if "patch_file" not in metafunc.fixturenames:
        return
    files = _corpus_files()
    if files:
        metafunc.parametrize("patch_file", files, ids=[f.name for f in files])
    else:
        metafunc.parametrize(
            "patch_file",
            [pytest.param(None, marks=pytest.mark.skip(
                reason="AMD ucode corpus not found; set AMD_UCODE_CORPUS"))],
        )


@pytest.fixture(scope="session")
def cmac_key() -> bytes:
    """
    The AES-CMAC key to verify signatures against, from ``$AMD_UCODE_CMAC_KEY``.

    No key is committed to this repository, so tests that need one skip unless
    the environment supplies it.
    """
    value = os.environ.get("AMD_UCODE_CMAC_KEY")
    if not value:
        pytest.skip("no CMAC key: set AMD_UCODE_CMAC_KEY to 32 hex characters")
    try:
        key = bytes.fromhex(value.strip().removeprefix("0x"))
    except ValueError:
        pytest.skip(f"AMD_UCODE_CMAC_KEY is not hexadecimal: {value!r}")
    if len(key) != 16:
        pytest.skip(f"AMD_UCODE_CMAC_KEY must be 16 bytes, got {len(key)}")
    return key
