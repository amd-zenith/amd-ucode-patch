#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
'''
A command line tool to inspect and verify AMD uCode patch signatures.
'''

import sys
import argparse
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from rich import box
from rich.console import Console
from rich.table import Table
from ..banner import BANNER
from ..parse import ucode_patch_parse
from .info import expand_paths

COLS = ["File", "Signed", "Digest", "Valid"]


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


def _row(path, key):
    """Return (row_cells, verdict) where verdict is True/False (key given) or None."""
    patch = ucode_patch_parse(path)
    signature = patch.header.signature

    if signature is None:
        return (str(path), "[yellow]no[/yellow]", "", "[dim]n/a[/dim]"), None

    recovered = signature.recover_digest()
    digest = recovered.hex() if recovered is not None else "[red]<bad padding>[/red]"

    if key is None:
        return (str(path), "[green]yes[/green]", digest, "[dim]not checked[/dim]"), None

    computed = CMAC.new(key, msg=patch.body.to_bytes(), ciphermod=AES).digest()
    verdict = recovered is not None and recovered == computed
    valid = "[green]yes[/green]" if verdict else "[red]no[/red]"
    return (str(path), "[green]yes[/green]", digest, valid), verdict


def main():
    console = Console()
    console.print(BANNER, highlight=False)

    parser = argparse.ArgumentParser(
        description="Inspect AMD microcode patch signatures; verify them when a key is provided.",
        epilog="The published Zen 1-4 CMAC key is 2b7e151628aed2a6abf7158809cf4f3c.",
    )
    parser.add_argument("files", nargs="+", help="Patch files to inspect")
    parser.add_argument(
        "-k", "--key", type=_parse_key, default=None,
        help="AES-128 CMAC key as hex (32 hex chars); enables signature verification",
    )
    args = parser.parse_args()

    table = Table(*COLS, box=box.HEAVY_HEAD)
    all_ok = True
    for path in expand_paths(args.files):
        try:
            row, verdict = _row(path, args.key)
            table.add_row(*row)
            if verdict is False:
                all_ok = False
        except Exception as e:
            console.log(f"Error reading {path}: {e}")
            all_ok = False
    console.print(table)

    # Non-zero only when a key was given and a signature failed to verify.
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
