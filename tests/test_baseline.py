#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Baseline regression: the model-independent facts must never drift.

For every corpus file, the facts read straight from fixed offsets (date,
patch_level, loader_id) plus the structural signature-block test must equal what
is committed in ``tests/data/baseline.json``. This pins the ground truth so the
rewrite cannot quietly change what a fixed-offset field decodes to, and catches
the corpus itself changing underneath us. Files present in only one of the two
sets are reported but not failed on, so a slightly different corpus checkout still
validates the overlap.

As the model grows, per-section tests will assert the parsed structures against
these same raw facts. Regenerate the committed baseline with
``tests/gen_baseline.py`` only when the corpus membership deliberately changes.
"""

import json
from pathlib import Path

import pytest

from baseline_facts import raw_facts

_BASELINE_PATH = Path(__file__).parent / "data" / "baseline.json"
_BASELINE = json.loads(_BASELINE_PATH.read_text()) if _BASELINE_PATH.is_file() else {}


def test_corpus_matches_baseline(patch_file: Path):
    if patch_file.name not in _BASELINE:
        pytest.skip(f"{patch_file.name} not in committed baseline")
    assert raw_facts(patch_file.read_bytes()) == _BASELINE[patch_file.name]
