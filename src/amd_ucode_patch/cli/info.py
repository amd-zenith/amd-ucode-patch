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
from amd_ucode_patch.structures.body_data_fam14to15 import BodyDataFam14to15
from amd_ucode_patch.structures.header_data import HeaderData
from amd_ucode_patch.structures.header_data_default import HeaderDataDefault
from amd_ucode_patch.structures.match_registers import MatchRegisters
from amd_ucode_patch.structures.patch import Patch

#: Columns follow the order of the fields in the patch: the prologue, then the
#: header data in offset order, then the signature block, the body header and
#: the body data, with derived values shown next to the field they come from.
COLS = ["File", "Date", "Patch level", "Loader ID",
        # the header data, offsets 10-31 in order
        "Size units", "Triads", "Init", "Checksum", "Req PL", "NB dev", "CPUID",
        # then the signature block, the body header and the body data
        "Signed", "Encrypted", "Body PL", "Match regs", "Op groups", "Size"]

#: Shown wherever a field is not defined by the patch's format.
_NA = "-"

#: The count and wholeness properties a modelled body exposes for its micro-op
#: group array, in the order they are looked for. The older families group
#: their ops in triads and Zen in quads, so the names differ; a body carries
#: at most one pair, and a body not modelled that far carries neither.
_OP_GROUP_FIELDS = (
    ("op_triad_count", "holds_whole_triads"),
    ("op_quad_count", "holds_whole_quads"),
)


def _field(data: HeaderData, name: str) -> object | None:
    """A header-data field, or ``None`` when this format does not model it."""
    return getattr(data, name, None)



def _declared_size_matches(patch: Patch, raw: bytes) -> bool | None:
    """
    Whether the size the header declares matches the file, or ``None`` where
    the format declares none.
    """
    declared = getattr(patch.header.data, "patch_size", None)
    return None if declared is None else declared == len(raw)


def _required_level_agrees(patch: Patch) -> bool | None:
    """
    Whether the patch level the header names as its prerequisite is consistent
    with the patch's own, or ``None`` where the format names none.

    It has to name the same processor and be older, or it is not a level this
    patch could be superseding.
    """
    required = getattr(patch.header.data, "required_patch_level", None)
    if required is None:
        return None
    own = patch.header.patch_level
    if required.cpuid is None or own.cpuid is None:
        return None
    return (required.cpuid.ucode_signature == own.cpuid.ucode_signature
            and required.value < own.value)


def _encryption_agrees(patch: Patch) -> bool | None:
    """
    Whether the body backs up the encrypted flag the header carries, or ``None``
    where the header carries no such flag.

    The families that carry it open their body with a frame that sits inside
    the encrypted region, so the frame decodes on a plaintext body and reads as
    ciphertext on an encrypted one. Agreeing means two independent signals say
    the same thing.
    """
    declared = patch.header.data.is_encrypted
    if declared is None:
        return None
    readable = BodyDataFam14to15.frame_is_readable(
        patch.body.to_bytes(), patch.header.patch_level)
    return readable is not declared


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
    How many ROM addresses the body's match registers name, and how many of
    those slots are in use. The Zen families pack two addresses into each
    register, so the total is not the register count.

    ``None`` means this format's body is not modelled that far, which is not the
    same as a body that carries no match registers. A body too short to hold the
    ones its family declares never reaches here: the parser refuses it, and the
    file is reported as a parse error instead of getting a row.
    """
    if registers is None:
        return _NA
    return f"{len(registers.used)}/{len(registers.addresses)}"


def _op_group_count(body_data) -> str:
    """
    How many whole micro-op groups the body's array holds, or ``_NA`` where
    the body is not modelled that far.

    This is what the body itself carves out, not what the header claims. On
    the triad families the header records the same count, and the "Triads"
    column shows that one; on Zen the header records none, so this is the only
    place the count appears.
    """
    for count_name, _ in _OP_GROUP_FIELDS:
        count = getattr(body_data, count_name, None)
        if count is not None:
            return str(count)
    return _NA


def _op_groups_are_whole(patch: Patch) -> bool | None:
    """
    Whether the micro-op array divides exactly into groups, or ``None`` where
    the body is not modelled that far. Bytes left over mean the array is not
    the length its geometry says it should be.
    """
    body_data = patch.body.body_data
    for count_name, whole_name in _OP_GROUP_FIELDS:
        if getattr(body_data, count_name, None) is not None:
            return bool(getattr(body_data, whole_name, False))
    return None


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

    size_units = _field(data, "patch_size_units")
    triads = _field(data, "op_triad_count")
    # The same "run the patch on load" signal lives in the pre-Zen header data
    # (``init_flag``) and in the Zen body header; show whichever one this format
    # carries. Only the triad families model the header one.
    init = _field(data, "init_flag")
    if init is None and body_header is not None:
        init = body_header.init_flag
    checksum = _field(data, "op_triad_checksum")
    cpuid = _field(data, "cpuid")
    required_pl = _field(data, "required_patch_level")
    nb_dev_id = _field(data, "nb_dev_id")
    pl_family = header.patch_level.family
    # The body knows whether it is encrypted whatever its format: the flag when
    # there is a body header to carry one, and plaintext when there is not. The
    # mirrored patch level does live only in the body header.
    encrypted = patch.body.is_encrypted
    # The body's copy of the header's patch level, wherever the format keeps
    # it: in the body header on the signed families, in the frame the body
    # opens with on Bobcat and Bulldozer.
    body_pl = (body_header.patch_level if body_header is not None
               else getattr(patch.body.body_data, "patch_level", None))
    # The match registers live in the body data, and only a plaintext body that
    # its family gives a count for has them; an encrypted one has no such field.
    match_registers = getattr(patch.body.body_data, "match_registers", None)

    cells = (
        str(path),
        str(header.date),
        f"{header.patch_level} (fam {pl_family:#04x})",
        str(header.loader_id),
        str(size_units) if size_units is not None else _NA,
        str(triads) if triads is not None else _NA,
        ("yes" if init else "no") if init is not None else _NA,
        f"{checksum:08x}" if checksum is not None else _NA,
        str(required_pl) if required_pl is not None else _NA,
        f"{nb_dev_id:08x}" if nb_dev_id is not None else _NA,
        f"{cpuid.ucode_signature:04x} ({cpuid.description})"
        if cpuid is not None else _NA,
        "yes" if header.signature is not None else "no",
        "yes" if encrypted else "no",
        str(body_pl) if body_pl is not None else _NA,
        _match_registers(match_registers),
        _op_group_count(patch.body.body_data),
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
    encryption_ok = _encryption_agrees(patch)
    if encryption_ok is not None:
        colours["Encrypted"] = "green" if encryption_ok else "red"
    size_ok = _declared_size_matches(patch, raw)
    if size_ok is not None:
        colours["Size units"] = "green" if size_ok else "red"
    required_ok = _required_level_agrees(patch)
    if required_ok is not None:
        colours["Req PL"] = "green" if required_ok else "red"
    groups_ok = _op_groups_are_whole(patch)
    if groups_ok is not None:
        colours["Op groups"] = "green" if groups_ok else "red"
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
