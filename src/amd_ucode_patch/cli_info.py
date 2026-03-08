#!/usr/bin/env python
'''
A command line tool to print information about an AMD uCode patch files.
'''

import glob
import argparse
from pathlib import Path
from rich import box
from rich.console import Console
from rich.table import Table
from .banner import BANNER
from .parse import ucode_patch_parse

COLS = ["File", "Date", "Upd. Rev", "Loader ID", "Proc. Rev", "CPUID", "Family", "Model", "Stepping", "Autorun", "Encrypted", "Body size"]


def expand_paths(patterns):
    for pattern in patterns:
        matches = sorted(glob.glob(pattern, recursive=True))
        if not matches:
            yield Path(pattern)
            continue
        for match in matches:
            yield Path(match)


def print_table(console: Console, paths, format):
    table = Table(*COLS, box=format)
    for path in paths:
        patch = ucode_patch_parse(path)
        table.add_row(
            str(path),
            f"{patch.header.year:04d}-{patch.header.month:02d}-{patch.header.day:02d}",
            f"{patch.header.update_revision:08x}",
            f"{patch.header.loader_id:04x}",
            f"{patch.header.processor_rev_id:04x}",
            patch.header.cpuid_str,
            f"0x{patch.header.cpu_family:02x}",
            f"0x{patch.header.cpu_model:02x}",
            f"0x{patch.header.cpu_stepping:02x}",
            f"{patch.verified_header.autorun}",
            f"{patch.verified_header.encrypted}",
            f"{len(patch.body)}",
        )
    console.print(table)


def print_csv(console: Console, paths):
    console.print(",".join(COLS))
    for path in paths:
        patch = ucode_patch_parse(path)
        console.print(",".join([
            str(path),
            f"{patch.header.year:04d}/{patch.header.month:02d}/{patch.header.day:02d}",
            f"{patch.header.update_revision:08x}",
            f"{patch.header.loader_id:04x}",
            f"{patch.header.processor_rev_id:04x}",
            patch.header.cpuid_str,
            f"0x{patch.header.cpu_family:02x}",
            f"0x{patch.header.cpu_model:02x}",
            f"0x{patch.header.cpu_stepping:02x}",
            f"{patch.verified_header.autorun}",
            f"{patch.verified_header.encrypted}",
            f"{len(patch.body)}",
        ]))


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
