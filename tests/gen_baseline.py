#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Regenerate ``tests/data/baseline.json`` from a corpus of patch files.

The baseline is the ground-truth fingerprint the parser is checked against (see
``tests/test_baseline.py``). Rerun this only when the corpus itself changes and
the new membership is intended -- never to paper over an unexpected diff.

Before regenerating, check *why* the baseline no longer matches. Only the
filenames changing (the collection renames files as the tool's canonical naming
evolves) is a safe reason; a changed fact for the same content is a real
regression and must not be papered over. Facts carry ``sha256_12``, so content
can be matched across a rename:

    old = json.load(open("tests/data/baseline.json"))
    by_sha = {f["sha256_12"]: f for f in old.values()}

Usage, with the corpus located the same way ``conftest.py`` locates it
(``$AMD_UCODE_CORPUS``, else ``../amd-ucode-collection/patches``)::

    python tests/gen_baseline.py [/path/to/amd-ucode-collection/patches]
"""

import json
import os
import sys
from pathlib import Path

#: This script lives in ``tests/``, so the repo root is two levels up.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_REPO_ROOT / "tests"))

from baseline_facts import raw_facts  # noqa: E402

_OUT = _REPO_ROOT / "tests" / "data" / "baseline.json"


def _default_corpus() -> Path:
    """Where ``conftest.py`` looks for the corpus, in the same order."""
    env = os.environ.get("AMD_UCODE_CORPUS")
    return Path(env) if env else _REPO_ROOT.parent / "amd-ucode-collection" / "patches"


def main() -> int:
    corpus = Path(sys.argv[1]) if len(sys.argv) > 1 else _default_corpus()
    files = sorted(corpus.glob("*.bin"))
    if not files:
        print(f"no *.bin patches under {corpus}", file=sys.stderr)
        return 1
    baseline = {p.name: raw_facts(p.read_bytes()) for p in files}

    if _OUT.is_file():
        old = json.loads(_OUT.read_text())
        by_sha = {f["sha256_12"]: f for f in old.values()}
        changed = [name for name, f in baseline.items()
                   if f["sha256_12"] in by_sha and by_sha[f["sha256_12"]] != f]
        gone = {f["sha256_12"] for f in old.values()} - {
            f["sha256_12"] for f in baseline.values()}
        added = {f["sha256_12"] for f in baseline.values()} - {
            f["sha256_12"] for f in old.values()}
        print(f"was {len(old)} entries, now {len(files)}: "
              f"{len(added)} new, {len(gone)} gone, {len(changed)} with changed facts")
        if changed:
            print("  WARNING: the facts below changed for unchanged content -- "
                  "that is a regression, not a rename:", file=sys.stderr)
            for name in changed[:10]:
                print(f"    {name}", file=sys.stderr)

    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(json.dumps(baseline, indent=1, sort_keys=True) + "\n")
    print(f"wrote {len(baseline)} entries to {_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
