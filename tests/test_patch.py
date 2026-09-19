#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""Baseline API of the top-level :class:`Patch` container."""

import hashlib
import struct

import pytest

from amd_ucode_patch.structures.patch import Patch
from amd_ucode_patch.structures.header import Header
from amd_ucode_patch.structures.header_data_default import HeaderDataDefault


def _core(loader_id: int) -> bytes:
    """A 32-byte core in the given format, with a distinct byte in every slot."""
    core = bytearray(range(Header.CORE_SIZE))
    struct.pack_into("<H", core, 8, loader_id)
    # patch level family 0x14 (Bobcat): an opaque body, no signature slot, so a
    # minimal core needs no trailing block to parse.
    struct.pack_into("<I", core, 4, 0x05000000)
    return bytes(core)


# A minimal well-formed buffer: a 32-byte core in an opaque format (no signature
# block is carved) plus some trailing body bytes.
_SAMPLE = _core(0x8000) + b"body-bytes"


def test_from_bytes_roundtrip():
    assert Patch.from_bytes(_SAMPLE).to_bytes() == _SAMPLE


def test_from_file_roundtrip(tmp_path):
    path = tmp_path / "patch.bin"
    path.write_bytes(_SAMPLE)
    assert Patch.from_file(path).to_bytes() == _SAMPLE


def test_to_file_roundtrip(tmp_path):
    path = tmp_path / "out.bin"
    Patch.from_bytes(_SAMPLE).to_file(path)
    assert path.read_bytes() == _SAMPLE


def test_from_bytes_copies_input():
    # A patch must not alias a caller's mutable buffer.
    buf = bytearray(_SAMPLE)
    patch = Patch.from_bytes(buf)
    buf[0] = 0xFF
    assert patch.to_bytes() == _SAMPLE


def test_splits_header_from_body():
    patch = Patch.from_bytes(_SAMPLE)
    assert patch.header.to_bytes() == _SAMPLE[:Header.CORE_SIZE]
    assert patch.body.to_bytes() == _SAMPLE[Header.CORE_SIZE:]


def test_rejects_short_buffer():
    with pytest.raises(ValueError):
        Patch.from_bytes(b"\x00" * (Header.CORE_SIZE - 1))


def test_unmodelled_family_parses_with_the_default_model():
    # A family with no model of its own still parses: the default header data
    # decodes the one field every format agrees on and keeps the rest verbatim,
    # so the patch round-trips without anything being guessed at. The loader id
    # is irrelevant now -- dispatch is by family (0x14 here, an opaque one).
    trailing = bytes(range(256)) * 3
    raw = _core(0x8099) + trailing
    patch = Patch.from_bytes(raw)
    assert isinstance(patch.header.data, HeaderDataDefault)
    assert patch.header.signature is None
    assert patch.body.to_bytes() == trailing
    assert patch.to_bytes() == raw


def test_sha256_is_the_hex_digest_of_the_bytes():
    patch = Patch.from_bytes(_SAMPLE)
    assert patch.sha256 == hashlib.sha256(_SAMPLE).hexdigest()
    assert len(patch.sha256) == 64


def test_sha256_tracks_edits():
    patch = Patch.from_bytes(_SAMPLE)
    before = patch.sha256
    patch.body.body_data.unknown0 = patch.body.body_data.unknown0 + b"\x00"
    assert patch.sha256 != before
