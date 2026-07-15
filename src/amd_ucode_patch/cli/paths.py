#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""Shared path handling for the command line tools."""

import glob
from pathlib import Path
from collections.abc import Iterable, Iterator


def expand_paths(patterns: Iterable[str]) -> Iterator[Path]:
    """
    Expand each glob pattern into the matching paths (sorted, recursive ``**``
    supported). A pattern with no matches is yielded verbatim as a ``Path`` so the
    caller can surface a sensible "file not found" error.
    """
    for pattern in patterns:
        matches = sorted(glob.glob(pattern, recursive=True))
        if not matches:
            yield Path(pattern)
            continue
        for match in matches:
            yield Path(match)
