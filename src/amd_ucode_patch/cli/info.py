#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
'''
A command line tool to print information about AMD uCode patch files.
'''

import argparse
from rich import box
from rich.console import Console
from rich.table import Table
from amd_ucode_patch.cli.banner import BANNER
from amd_ucode_patch.cli.paths import expand_paths
from amd_ucode_patch.parse import ucode_patch_parse
from amd_ucode_patch.structures.patch_level import PatchLevelV2

COLS = ["File", "Date", "Patch level", "PL Ver", "PL Rev", "Loader ID", "Proc. Rev", "CPUID", "Family", "Family Name", "Model", "Stepping", "Microarch", "Codename", "Signed", "Autorun", "Encrypted", "Body size"]


def _row_fields(path, patch):
    patch_level = patch.header.patch_level
    # Advanced (v2 / Zen+) patch level fields are only meaningful when present.
    patch_rev = f"{patch_level.rev:02x}" if isinstance(patch_level, PatchLevelV2) else ""
    return (
        str(path),
        str(patch.header.date),
        str(patch_level),
        f"v{int(patch_level.version)}",
        patch_rev,
        f"{patch.header.loader_id:04x}",
        f"{patch.header.cpuid.ucode_signature:04x}",
        f"{patch.header.cpuid.cpuid_signature:08X}",
        f"0x{patch.header.cpuid.family:02x}",
        patch.header.cpuid.familyname,
        f"0x{patch.header.cpuid.model:02x}",
        f"0x{patch.header.cpuid.stepping:02x}",
        patch.header.cpuid.microarchitecture,
        patch.header.cpuid.codename,
        "yes" if patch.header.signature is not None else "no",
        f"{patch.body.verified_header.autorun if patch.body.verified_header is not None else ''}",
        f"{patch.body.verified_header.encrypted if patch.body.verified_header is not None else ''}",
        f"{len(patch.body.data)}",
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
