#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path
from .structures.ucode_patch import UcodePatch

def ucode_patch_parse(file: Path) -> UcodePatch:
    with file.open("rb") as f:
        return UcodePatch.from_bytes(f.read())
