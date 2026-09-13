#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Model-independent facts about a patch file, used by the baseline regression.

These are the things any correct parser must agree on regardless of how it models
the format: they are read straight from fixed offsets, plus a key-free structural
test for the signature block. Deliberately *not* included are model-dependent
interpretations (cpuid vs equivalence id, family, match-register slicing) — those
change by design during the refactor and are covered by their own tests.

Shared by ``tools/gen_baseline.py`` (which writes ``tests/data/baseline.json``)
and ``tests/test_baseline.py`` (which checks the corpus still matches it), so the
two can never disagree on what a "fact" is.
"""

import hashlib
import struct

from amd_ucode_patch.utils.rsa import recover_pkcs1_v15_payload

#: Fixed offsets of the shared prologue (identical framing in every known format)
#: and of the Zen signature block.
_PROLOGUE_FMT = "<IIH"  # date (u32), patch_level (u32), loader_id (u16)
_SIG_OFF, _MOD_OFF, _BODY_OFF = 32, 288, 800


def has_signature_block(buf: bytes) -> bool:
    """
    Key-free structural test: does ``sig ** 0x10001 mod modulus`` (offsets 32 and
    288) unpad as PKCS#1 v1.5? Random/encrypted bytes pass with negligible
    probability, so unlike an entropy threshold this does not false-positive on an
    encrypted pre-Zen body.
    """
    if len(buf) < _BODY_OFF:
        return False
    try:
        return recover_pkcs1_v15_payload(buf[_SIG_OFF:_MOD_OFF], buf[_MOD_OFF:_MOD_OFF + 256]) is not None
    except Exception:
        return False


def raw_facts(buf: bytes) -> dict:
    """Model-independent facts about one patch file."""
    date, patch_level, loader_id = struct.unpack_from(_PROLOGUE_FMT, buf, 0)
    return {
        "size": len(buf),
        "sha256_12": hashlib.sha256(buf).hexdigest()[:12],
        "date": f"{date:08x}",
        "patch_level": f"{patch_level:08x}",
        "loader_id": f"{loader_id:04x}",
        "signed": has_signature_block(buf),
    }
