#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
'''
A command line tool to inspect, verify, sign and resign AMD uCode patches.
'''

import sys
import argparse
from pathlib import Path
from rich import box
from rich.console import Console
from rich.table import Table
from amd_ucode_patch.cli.banner import BANNER
from amd_ucode_patch.parse import ucode_patch_parse
from amd_ucode_patch.utils.cmac import cmac_digest
from amd_ucode_patch.utils.entrysign import produce_colliding_key
from amd_ucode_patch.utils.rsa import montgomery_n_prime, sign_pkcs1_v15_payload
from amd_ucode_patch.cli.paths import expand_paths
from amd_ucode_patch.cli.argtypes import parse_key, parse_modulus, parse_private


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


def _write_target(src: Path, output: Path | None) -> Path:
    return output if output is not None else src


def _resign_one(
    path: Path,
    key: bytes,
    private: bytes | None,
    modulus: bytes | None,
    output: Path | None,
) -> tuple[Path, str]:
    patch = ucode_patch_parse(path)
    signature = patch.header.signature
    if signature is None:
        raise ValueError("patch is unsigned (pre-Zen), cannot resign")

    digest = cmac_digest(patch.body.to_bytes(), key)
    if private is None:
        target = cmac_digest(signature.modulus, key)
        new_modulus, new_private = produce_colliding_key(target, cmac_key=key)
    else:
        new_modulus = modulus if modulus is not None else signature.modulus
        new_private = private

    signature.modulus = new_modulus
    signature.check = montgomery_n_prime(new_modulus)
    signature.signature = sign_pkcs1_v15_payload(digest, new_modulus, new_private)

    out_path = _write_target(path, output)
    out_path.write_bytes(patch.to_bytes())
    return out_path, digest.hex()


def resign(args, console) -> int:
    """
    Process the ``resign`` command: re-sign edited patches, in place by default.
    Returns a process exit code (non-zero if any file failed or the arguments
    were invalid).
    """
    if args.output is not None and len(args.files) != 1:
        console.log("Error: --output is only allowed with a single input file")
        return 1
    if args.modulus is not None and args.private is None:
        console.log("Error: --modulus requires --private")
        return 1

    exit_code = 0
    for path in expand_paths(args.files):
        try:
            target, digest = _resign_one(
                path,
                args.key,
                args.private,
                args.modulus,
                args.output,
            )
            console.print(f"[green]resigned[/green] {target} digest={digest}")
        except Exception as e:
            console.log(f"Error resigning {path}: {e}")
            exit_code = 1
    return exit_code


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

    resign_parser = subparsers.add_parser("resign", help="Re-sign edited patches in-place (zentool-style)")
    resign_parser.add_argument("files", nargs="+", help="Patch files to resign")
    resign_parser.add_argument("-k", "--key", type=parse_key, required=True, help="AES-128 CMAC key as hex (default: published Zen 1-4 key)")
    resign_parser.add_argument("-d", "--private", type=parse_private, default=None, help="RSA private exponent as 512 hex chars (256 bytes). Optional.")
    resign_parser.add_argument("-m", "--modulus", type=parse_modulus, default=None, help="RSA modulus as 512 hex chars (256 bytes). Used with --private.")
    resign_parser.add_argument("-o", "--output", type=Path, default=None, help="Output file (single-input only). Defaults to in-place rewrite")

    args = parser.parse_args()

    if args.command == "verify":
        verify(args, console)
    elif args.command == "resign":
        sys.exit(resign(args, console))
    else:
        console.log(f"Error: unknown command {args.command!r}")


if __name__ == "__main__":
    main()
