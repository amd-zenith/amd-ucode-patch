#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
A command line tool to verify and resign AMD uCode patch signatures.
"""

import sys
import argparse
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

from amd_ucode_patch.cli.argtypes import parse_key, parse_modulus, parse_private
from amd_ucode_patch.cli.banner import BANNER
from amd_ucode_patch.cli.paths import expand_paths
from amd_ucode_patch.structures.patch import Patch
from amd_ucode_patch.structures.signature_fam17plus import SignatureFam17Plus
from amd_ucode_patch.utils.cmac import cmac_digest
from amd_ucode_patch.utils.entrysign import produce_colliding_key
from amd_ucode_patch.utils.rsa import montgomery_n_prime, sign_pkcs1_v15_payload

COLS = ["File", "Signed", "Digest", "Valid"]


def _verify_row(path: Path, key: bytes | None) -> tuple[str, ...]:
    """The four display cells (File, Signed, Digest, Valid) for one patch."""
    patch = Patch.from_bytes(path.read_bytes())
    signature = patch.header.signature

    if signature is None:
        return (str(path), "[yellow]no[/yellow]", "", "[dim]n/a[/dim]")

    if not isinstance(signature, SignatureFam17Plus):
        # A signature slot that is not the RSA block (family 0x16): present, but
        # nothing to recover or verify.
        return (str(path), "[green]yes[/green]", "[dim]not RSA[/dim]",
                "[dim]n/a[/dim]")

    recovered = signature.recover_digest()
    digest = recovered.hex() if recovered is not None else "[red]<bad padding>[/red]"

    if key is None:
        return (str(path), "[green]yes[/green]", digest, "[dim]not checked[/dim]")

    verified = patch.signature_verifies(key)
    valid = "[green]yes[/green]" if verified else "[red]no[/red]"
    return (str(path), "[green]yes[/green]", digest, valid)


def verify(args, console: Console) -> None:
    """The ``verify`` command: print a signature table for each file."""
    table = Table(*COLS, box=box.HEAVY_HEAD)
    for path in expand_paths(args.files):
        try:
            table.add_row(*_verify_row(path, args.key))
        except Exception as exc:                                   # noqa: BLE001
            console.log(f"Error reading {path}: {exc}")
    console.print(table)


def _resign_one(
    path: Path,
    key: bytes,
    private: bytes | None,
    modulus: bytes | None,
    output: Path | None,
) -> tuple[Path, str]:
    """Resign one patch, returning where it was written and the signed digest."""
    patch = Patch.from_bytes(path.read_bytes())
    signature = patch.header.signature
    if not isinstance(signature, SignatureFam17Plus):
        raise ValueError("patch has no RSA signature to resign")

    digest = cmac_digest(patch.body.to_bytes(), key)
    if private is None:
        # No private key given.
        # Forge a modulus that collides to the CMAC the
        # loader expects, the way zentool does for the EntrySign exploit.
        target = cmac_digest(signature.modulus, key)
        new_modulus, new_private = produce_colliding_key(target, cmac_key=key)
    else:
        new_modulus = modulus if modulus is not None else signature.modulus
        new_private = private

    signature.modulus = new_modulus
    signature.check = montgomery_n_prime(new_modulus)
    signature.signature = sign_pkcs1_v15_payload(digest, new_modulus, new_private)

    out_path = output if output is not None else path
    out_path.write_bytes(patch.to_bytes())
    return out_path, digest.hex()


def resign(args, console: Console) -> int:
    """
    The ``resign`` command: re-sign edited patches, in place by default.

    Returns a process exit code, non-zero if any file failed or the arguments
    were invalid.
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
                path, args.key, args.private, args.modulus, args.output
            )
            console.print(f"[green]resigned[/green] {target} digest={digest}")
        except Exception as exc:                                   # noqa: BLE001
            console.log(f"Error resigning {path}: {exc}")
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

    verify_parser = subparsers.add_parser("verify", help="Inspect signatures, and verify against the body with -k")
    verify_parser.add_argument("files", nargs="+", help="Patch files to inspect")
    verify_parser.add_argument("-k", "--key", type=parse_key, default=None, help="AES-128 CMAC key as 32 hex chars. Enables body verification.")

    resign_parser = subparsers.add_parser("resign", help="Re-sign edited patches in-place (zentool-style)")
    resign_parser.add_argument("files", nargs="+", help="Patch files to resign")
    resign_parser.add_argument("-k", "--key", type=parse_key, required=True, help="AES-128 CMAC key as 32 hex chars")
    resign_parser.add_argument("-d", "--private", type=parse_private, default=None, help="RSA private exponent as 512 hex chars (256 bytes). Optional.")
    resign_parser.add_argument("-m", "--modulus", type=parse_modulus, default=None, help="RSA modulus as 512 hex chars (256 bytes). Used with --private.")
    resign_parser.add_argument("-o", "--output", type=Path, default=None, help="Output file (single-input only). Defaults to in-place rewrite")

    args = parser.parse_args()

    if args.command == "verify":
        verify(args, console)
    elif args.command == "resign":
        sys.exit(resign(args, console))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
