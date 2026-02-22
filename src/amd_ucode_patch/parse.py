#!/usr/bin/env python

from pathlib import Path
from .structures.ucode_patch import UcodePatch

def ucode_patch_parse(file: Path) -> UcodePatch:
    with file.open("rb") as f:
        return UcodePatch.from_bytes(f.read())
