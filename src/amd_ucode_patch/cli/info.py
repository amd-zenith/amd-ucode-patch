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
from amd_ucode_patch.structures.header_data_default import HeaderDataDefault
from amd_ucode_patch.structures.match_registers import MatchRegisters
from amd_ucode_patch.structures.patch import Patch

#: Columns follow the order of the fields in the patch: the prologue, then the
#: header data in offset order, then the signature block, the body header and
#: the body data, with derived values shown next to the field they come from.
COLS = ["File", "Date", "Patch level", "Loader ID",
        # the header data, offsets 10-31 in order
        "Triads", "Init", "Checksum", "NB dev", "CPUID",
        # then the signature block, the body header and the body data
        "Signed", "Encrypted", "Body PL", "Match regs", "Size"]

#: Shown wherever a field is not defined by the patch's format.
_NA = "-"


def _field(data: HeaderData, name: str) -> object | None:
    """A header-data field, or ``None`` when this format does not model it."""
    return getattr(data, name, None)



def _triad_count_matches(patch: Patch) -> bool | None:
    """
    Whether the triad count the header records matches the array the body
    carves out, or ``None`` when this format carries neither.

    Both halves have to agree: the array must divide exactly into triads, and
    there must be as many as the header claims.
    """
    stored = _field(patch.header.data, "op_triad_count")
    body_data = patch.body.body_data
    counted = getattr(body_data, "op_triad_count", None)
    if stored is None or counted is None:
        return None
    return bool(getattr(body_data, "holds_whole_triads", False)) and counted == stored


def _checksum_matches(patch: Patch) -> bool | None:
    """
    Whether the checksum the header stores matches the one computed from the
    body it covers, or ``None`` when this format carries neither.
    """
    stored = _field(patch.header.data, "op_triad_checksum")
    if stored is None:
        return None
    try:
        computed = patch.body.body_data.op_triad_checksum
    except (AttributeError, ValueError):
        return None
    return computed == stored


def _match_registers(registers: MatchRegisters | None) -> str:
    """
    How many match registers the body opens with, and how many are in use.

    ``None`` means this format's body is not modelled that far, which is not the
    same as a body that carries no match registers. A body too short to hold the
    ones its family declares never reaches here: the parser refuses it, and the
    file is reported as a parse error instead of getting a row.
    """
    if registers is None:
        return _NA
    return f"{len(registers.used)}/{registers.count}"


def _row_fields(path, raw: bytes) -> tuple[tuple[str, ...], dict[str, str], bool]:
    """
    One table row for ``path``, plus a map of column -> "green"/"red" for the
    cells whose value is cross-checked, plus whether this patch fell back to the
    default header-data model.
    """
    patch = Patch.from_bytes(raw)
    header = patch.header
    data = header.data
    body_header = patch.body.body_header

    triads = _field(data, "op_triad_count")
    # The same "run the patch on load" signal lives in the pre-Zen header data
    # (``init_flag``) and in the Zen body header; show whichever one this format
    # carries. Only the triad families model the header one.
    init = _field(data, "init_flag")
    if init is None and body_header is not None:
        init = body_header.init_flag
    checksum = _field(data, "op_triad_checksum")
    cpuid = _field(data, "cpuid")
    nb_dev_id = _field(data, "nb_dev_id")
    pl_family = header.patch_level.family
    # The body knows whether it is encrypted whatever its format: the flag when
    # there is a body header to carry one, and plaintext when there is not. The
    # mirrored patch level does live only in the body header.
    encrypted = patch.body.is_encrypted
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
        f"{nb_dev_id:08x}" if nb_dev_id is not None else _NA,
        f"{cpuid.ucode_signature:04x} ({cpuid.description})"
        if cpuid is not None else _NA,
        "yes" if header.signature is not None else "no",
        "yes" if encrypted else "no",
        str(body_pl) if body_pl is not None else _NA,
        _match_registers(match_registers),
        str(len(raw)),
    )

    colours: dict[str, str] = {}
    # Flag the known-malformed patch levels red; every other one is well-formed.
    colours["Patch level"] = (
        "red" if header.patch_level.is_anomalous else "green"
    )
    triads_ok = _triad_count_matches(patch)
    if triads_ok is not None:
        colours["Triads"] = "green" if triads_ok else "red"
    checksum_ok = _checksum_matches(patch)
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
    return cells, colours, isinstance(data, HeaderDataDefault)


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
            cells, colours, is_default = _row_fields(path, raw)
        except Exception as exc:                                   # noqa: BLE001
            # A malformed file gets no row -- the parser refused it -- so this
            # line is the only place it shows up. Red, so it is not missed.
            console.log(f"[red]Error parsing {path}: {exc}[/red]")
            continue
        unmodelled += is_default
        yield cells, colours
    if unmodelled:
        console.log(f"{unmodelled} file(s): that format has no header-data model "
                    f"of its own, so the field names shown come from the shared "
                    f"AMD header rather than from a model verified for it")


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
