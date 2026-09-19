#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
A command line tool to print information about AMD uCode patch files.

A format with no header-data model of its own still parses, with the fields
only that format defines left empty.
"""

import argparse
import csv
import sys

from rich import box
from rich.console import Console
from rich.table import Table

from amd_ucode_patch.cli.banner import BANNER
from amd_ucode_patch.cli.paths import expand_paths
from amd_ucode_patch.structures.header_data import HeaderData
from amd_ucode_patch.structures.patch import Patch

#: Columns follow the order of the fields in the patch: the prologue, then the
#: header data in offset order, then the signature block, the body header and
#: the body data, with derived values shown next to the field they come from.
COLS = ["File", "Date", "Patch level", "Loader ID", "Triads", "Init",
        "Checksum", "CPUID", "Signed", "Encrypted", "Body PL", "Match regs",
        "Size"]

#: Shown wherever a field is not defined by the patch's format.
_NA = "-"


def _field(data: HeaderData, name: str) -> object | None:
    """A header-data field, or ``None`` when this format does not model it."""
    return getattr(data, name, None)


def _checksum_matches(data: HeaderData, raw: bytes) -> bool | None:
    """
    Whether the stored checksum matches the content it covers, or ``None`` when
    this format has no checksum or the patch is too short to compute one.
    """
    stored = _field(data, "op_triad_checksum")
    compute = getattr(data, "compute_op_triad_checksum", None)
    if stored is None or compute is None:
        return None
    try:
        return compute(raw) == stored
    except ValueError:
        return None


def _match_registers(registers: list[int] | None) -> str:
    """
    How many match registers the body opens with.

    ``None`` means this format's body is not modelled that far, which is not the
    same as a body that carries no match registers. A body too short to hold the
    ones its family declares never reaches here: the parser refuses it, and the
    file is reported as a parse error instead of getting a row.
    """
    return _NA if registers is None else str(len(registers))


def _row_fields(path, raw: bytes) -> tuple[tuple[str, ...], dict[str, str]]:
    """
    One table row for ``path``, filling what the patch's format supports, plus a
    map of column -> "green"/"red" for the cells whose value is cross-checked.
    """
    patch = Patch.from_bytes(raw)
    header = patch.header
    data = header.data
    body_header = patch.body.body_header

    triads = _field(data, "op_triad_count")
    # The same "run the patch on load" signal lives in the pre-Zen header data
    # (``init_flag``) and in the Zen body header; show whichever one this format
    # carries.
    init = _field(data, "init_flag")
    if init is None and body_header is not None:
        init = body_header.init_flag
    checksum = _field(data, "op_triad_checksum")
    cpuid = _field(data, "cpuid")
    pl_family = header.patch_level.family
    # ``encrypted`` and the mirrored patch level live only in the body header.
    encrypted = body_header.encrypted if body_header is not None else None
    body_pl = body_header.patch_level if body_header is not None else None
    # The match registers live in the body data, and only a plaintext body that
    # its family gives a count for has them; an encrypted one has no such field.
    match_registers = getattr(patch.body.body_data, "match_registers", None)

    cells = (
        str(path),
        str(header.date),
        f"{header.patch_level} (fam {pl_family:#04x})",
        str(header.loader_id),
        str(triads) if triads is not None else _NA,
        ("yes" if init else "no") if init is not None else _NA,
        f"{checksum:08x}" if checksum is not None else _NA,
        f"{cpuid.ucode_signature:04x} ({cpuid.description})"
        if cpuid is not None else _NA,
        "yes" if header.signature is not None else "no",
        ("yes" if encrypted else "no") if encrypted is not None else _NA,
        str(body_pl) if body_pl is not None else _NA,
        _match_registers(match_registers),
        str(len(raw)),
    )

    colours: dict[str, str] = {}
    # Flag the known-malformed patch levels red; every other one is well-formed.
    colours["Patch level"] = (
        "red" if header.patch_level.is_anomalous else "green"
    )
    checksum_ok = _checksum_matches(data, raw)
    if checksum_ok is not None:
        colours["Checksum"] = "green" if checksum_ok else "red"
    # Cross-check the patch level against the header's CPUID field. Newer patch
    # levels pack the whole CPUID, so the whole signature is checked; older ones
    # carry only the family, so just that is.
    pl_cpuid = header.patch_level.cpuid
    if cpuid is not None:
        if pl_cpuid is not None:
            matches = pl_cpuid.ucode_signature == cpuid.ucode_signature
        else:
            matches = pl_family == cpuid.family
        colours["CPUID"] = "green" if matches else "red"
    if body_pl is not None:
        # The body header's patch level should mirror the header's.
        matches = body_pl.value == header.patch_level.value
        colours["Body PL"] = "green" if matches else "red"
    return cells, colours


def _rows(paths):
    """
    Build a row per readable patch, with its checksum verdict.

    Diagnostics go to stderr so that piping the table or the CSV somewhere
    yields only the data.
    """
    console = Console(stderr=True)
    unmodelled = 0
    for path in paths:
        try:
            raw = path.read_bytes()
            cells, colours = _row_fields(path, raw)
        except Exception as exc:                                   # noqa: BLE001
            # A malformed file gets no row -- the parser refused it -- so this
            # line is the only place it shows up. Red, so it is not missed.
            console.log(f"[red]Error parsing {path}: {exc}[/red]")
            continue
        unmodelled += cells[COLS.index("Triads")] == _NA
        yield cells, colours
    if unmodelled:
        console.log(f"{unmodelled} file(s): that format has no header-data "
                    f"model of its own, so only shared fields are shown")


def _apply_colours(cells: tuple[str, ...], colours: dict[str, str]) -> list[str]:
    """Wrap each cross-checked cell in its verdict colour (green/red)."""
    out = list(cells)
    for column, colour in colours.items():
        index = COLS.index(column)
        out[index] = f"[{colour}]{out[index]}[/{colour}]"
    return out


def print_table(console: Console, paths, format):
    table = Table(*COLS, box=format)
    for cells, colours in _rows(paths):
        table.add_row(*_apply_colours(cells, colours))
    console.print(table)


def print_csv(paths):
    """
    Write the rows as CSV to stdout.

    Written with :mod:`csv` rather than through the console: cell values contain
    commas (a processor description, for one), and machine-readable output
    should carry neither console formatting nor the checksum colouring.
    """
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(COLS)
    writer.writerows(cells for cells, _ in _rows(paths))


def main():
    console = Console()

    parser = argparse.ArgumentParser(description="Inspect AMD microcode patch files.")
    parser.add_argument("files", nargs="+", help="Patch files to inspect")
    parser.add_argument("-f", "--format", choices=["text", "md", "csv"], default="text")
    args = parser.parse_args()

    if args.format != "csv":
        console.print(BANNER, highlight=False)

    paths = expand_paths(args.files)
    if args.format == "text":
        print_table(console, paths, box.HEAVY_HEAD)
    elif args.format == "md":
        print_table(console, paths, box.MARKDOWN)
    elif args.format == "csv":
        print_csv(paths)


if __name__ == "__main__":
    main()
