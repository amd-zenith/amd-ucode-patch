#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from .structures.ucode_patch import UcodePatch

def ucode_patch_name(patch: UcodePatch, enc_override=None) -> str:
    # Format should be:
    # family<family>_cpuid<cpuid>_rev<revision>_date<yyyymmdd>_enc<ee>.bin
    # The _enc<ee> suffix is only present when a verified header exists.
    name = f"family{patch.header.cpu_family:02x}_cpuid{patch.header.cpuid_str}_rev{patch.header.update_revision:08x}_date{patch.header.year:04}{patch.header.month:02}{patch.header.day:02}"
    if patch.verified_header is not None:
        enc = patch.verified_header.encrypted if enc_override is None else enc_override
        name += f"_enc{enc:02}"
    name += ".bin"
    return name
