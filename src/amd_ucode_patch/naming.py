#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

from .structures.patch import Patch

def ucode_patch_name(patch: Patch, enc_override=None) -> str:
    # Format should be:
    # family<family>_cpuid<cpuid>_rev<revision>_date<yyyymmdd>_enc<ee>.bin
    # The _enc<ee> suffix is only present when a verified header exists.
    cpuid = patch.header.cpuid
    name = f"family{cpuid.family:02x}_cpuid{cpuid.cpuid_signature:08X}_rev{patch.header.patch_level}_date{patch.header.date.year:04}{patch.header.date.month:02}{patch.header.date.day:02}"
    if patch.body.verified_header is not None:
        enc = patch.body.verified_header.encrypted if enc_override is None else enc_override
        name += f"_enc{enc:02}"
    name += ".bin"
    return name
