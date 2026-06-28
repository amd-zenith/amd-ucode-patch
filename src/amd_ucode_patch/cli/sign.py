#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
'''
A command line tool to verify AMD uCode patch signatures with a provided key.
'''

import sys
import argparse
from rich import box
from rich.console import Console
from rich.table import Table
from ..banner import BANNER
from ..parse import ucode_patch_parse
from .info import expand_paths

COLS = ["File", "Signed", "Valid"]


def _parse_key(value: str) -> bytes:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"key must be hexadecimal, got {value!r}")
    if len(key) != 16:
        raise argparse.ArgumentTypeError(
            f"key must be 16 bytes (32 hex chars), got {len(key)}"
        )
    return key


def _verify_row(path, key):
    """Return (row_fields, ok) where ok is False only for a present-but-failing signature."""
    patch = ucode_patch_parse(path)
    signed = patch.header.signature is not None
    result = patch.signature_verifies(key)
    if result is None:
        valid = "n/a"
    else:
        valid = "yes" if result else "no"
    return (str(path), "yes" if signed else "no", valid), result is not False


def main():
    console = Console()
    console.print(BANNER, highlight=False)

    parser = argparse.ArgumentParser(description="AMD microcode patch signature handling."
    )
    parser.add_argument("files", nargs="+", help="Patch files to verify")
    parser.add_argument(
        "-k", "--key", required=True, type=_parse_key,
        help="AES-128 CMAC key as hex (32 hex chars)",
    )
    args = parser.parse_args()

    table = Table(*COLS, box=box.HEAVY_HEAD)
    all_ok = True
    for path in expand_paths(args.files):
        try:
            row, ok = _verify_row(path, args.key)
            table.add_row(*row)
            all_ok = all_ok and ok
        except Exception as e:
            console.log(f"Error verifying {path}: {e}")
            all_ok = False
    console.print(table)

    # Exit non-zero if any present signature failed to verify (n/a does not count).
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
