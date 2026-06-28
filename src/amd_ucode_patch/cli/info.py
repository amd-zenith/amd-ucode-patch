#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
'''
A command line tool to print information about AMD uCode patch files.
'''

import glob
import argparse
from pathlib import Path
from rich import box
from rich.console import Console
from rich.table import Table
from ..banner import BANNER
from ..parse import ucode_patch_parse

COLS = ["File", "Date", "Upd. Rev", "Loader ID", "Proc. Rev", "CPUID", "Family", "Family Name", "Microarch", "Codename", "Model", "Stepping", "Autorun", "Encrypted", "Body size"]


def expand_paths(patterns):
    for pattern in patterns:
        matches = sorted(glob.glob(pattern, recursive=True))
        if not matches:
            yield Path(pattern)
            continue
        for match in matches:
            yield Path(match)


def _row_fields(path, patch):
    return (
        str(path),
        str(patch.header.date),
        f"{patch.header.update_revision:08x}",
        f"{patch.header.loader_id:04x}",
        f"{patch.header.cpuid.ucode_signature:04x}",
        f"{patch.header.cpuid.cpuid_signature:08X}",
        f"0x{patch.header.cpuid.family:02x}",
        patch.header.cpuid.familyname,
        patch.header.cpuid.microarchitecture,
        patch.header.cpuid.codename,
        f"0x{patch.header.cpuid.model:02x}",
        f"0x{patch.header.cpuid.stepping:02x}",
        f"{patch.verified_header.autorun if patch.verified_header is not None else ''}",
        f"{patch.verified_header.encrypted if patch.verified_header is not None else ''}",
        f"{len(patch.body)}",
    )

def print_table(console: Console, paths, format):
    table = Table(*COLS, box=format)
    for path in paths:
        try:
            patch = ucode_patch_parse(path)
            table.add_row(*_row_fields(path, patch))
        except Exception as e:
            console.log(f"Error parsing {path}: {e}")
    console.print(table)


def print_csv(console: Console, paths):
    console.print(",".join(COLS))
    for path in paths:
        patch = ucode_patch_parse(path)
        console.print(",".join(_row_fields(path, patch)))


def main():
    console = Console()
    console.print(BANNER, highlight=False)

    parser = argparse.ArgumentParser(description="Inspect AMD microcode patch files.")
    parser.add_argument("files", nargs="+", help="Patch files to inspect")
    parser.add_argument("-f", "--format", choices=["text", "md", "csv"], default="text")
    args = parser.parse_args()

    paths = expand_paths(args.files)
    if args.format == "text":
        print_table(console, paths, box.HEAVY_HEAD)
    elif args.format == "md":
        print_table(console, paths, box.MARKDOWN)
    elif args.format == "csv":
        print_csv(console, paths)


if __name__ == "__main__":
    main()
