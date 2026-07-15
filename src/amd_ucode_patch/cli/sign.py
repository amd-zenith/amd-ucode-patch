#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
'''
A command line tool to inspect, verify, sign and resign AMD uCode patches.
'''

import argparse
from rich import box
from rich.console import Console
from rich.table import Table
from amd_ucode_patch.cli.banner import BANNER
from amd_ucode_patch.parse import ucode_patch_parse
from amd_ucode_patch.utils.cmac import cmac_digest
from amd_ucode_patch.cli.paths import expand_paths
from amd_ucode_patch.cli.argtypes import parse_key


COLS = ["File", "Signed", "Digest", "Valid"]


def _verify_row(path, key):
    """Return the four display cells (File, Signed, Digest, Valid) for one patch."""
    patch = ucode_patch_parse(path)
    signature = patch.header.signature

    if signature is None:
        return (str(path), "[yellow]no[/yellow]", "", "[dim]n/a[/dim]")

    recovered = signature.recover_digest()
    digest = recovered.hex() if recovered is not None else "[red]<bad padding>[/red]"

    if key is None:
        return (str(path), "[green]yes[/green]", digest, "[dim]not checked[/dim]")

    computed = cmac_digest(patch.body.to_bytes(), key)
    verdict = recovered is not None and recovered == computed
    valid = "[green]yes[/green]" if verdict else "[red]no[/red]"
    return (str(path), "[green]yes[/green]", digest, valid)


def verify(args, console):
    """Process the ``verify`` command: print a signature table for each file."""
    table = Table(*COLS, box=box.HEAVY_HEAD)
    for path in expand_paths(args.files):
        try:
            row = _verify_row(path, args.key)
            table.add_row(*row)
        except Exception as e:
            console.log(f"Error reading {path}: {e}")
    console.print(table)


def main():
    console = Console()
    console.print(BANNER, highlight=False)

    parser = argparse.ArgumentParser(
        description="Inspect, verify, sign and resign AMD microcode patch signatures.",
        epilog="The published Zen 1-4 CMAC key is 2b7e151628aed2a6abf7158809cf4f3c.",
    )

    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser("verify", help="Inspect signatures and verify with -k when provided")
    verify_parser.add_argument("files", nargs="+", help="Patch files to inspect")
    verify_parser.add_argument("-k", "--key", type=parse_key, default=None, help="AES-128 CMAC key as hex (32 hex chars); enables verification")

    args = parser.parse_args()

    if args.command == "verify":
        verify(args, console)
    else:
        console.log(f"Error: unknown command {args.command!r}")


if __name__ == "__main__":
    main()
