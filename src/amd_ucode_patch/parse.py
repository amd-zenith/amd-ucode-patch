#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path
from .structures.patch import Patch

def ucode_patch_parse(file: Path) -> Patch:
    with file.open("rb") as f:
        return Patch.from_bytes(f.read())
