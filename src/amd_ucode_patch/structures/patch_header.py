#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from dataclasses import dataclass
from amd_cpuid import AmdCpuId
from amd_ucode_patch.structures.patch_date import PatchDate
from amd_ucode_patch.structures.patch_level import PatchLevel


@dataclass
class PatchHeader:
    '''
    https://github.com/torvalds/linux/blob/3544d5ce36f403db6e5c994f526101c870ffe9fe/arch/x86/kernel/cpu/microcode/amd.c#L70
    
    Original structure:
    struct microcode_header_amd {
        u32	data_code;
        u32	patch_id;
        u16	mc_patch_data_id;
        u8	mc_patch_data_len;
        u8	init_flag;
        u32	mc_patch_data_checksum;
        u32	nb_dev_id;
        u32	sb_dev_id;
        u16	processor_rev_id;
        u8	nb_rev_id;
        u8	sb_rev_id;
        u8	bios_api_rev;
        u8	reserved1[3];
        u32	match_reg[8];
    } __packed;

    data_code is in reality a date. We split that into u16, u8, u8.
    patch_id is referred to as revision in many other places.
    '''
    # Fields after the leading PatchDate (data_code) and PatchLevel (patch_id).
    FMT = "<HBB I II H BBBBBB"
    SIZE = PatchDate.SIZE + PatchLevel.SIZE + struct.calcsize(FMT)

    date: PatchDate
    patch_level: PatchLevel
    loader_id: int
    unk0: int
    unk1: int
    unk2: int
    unk3: int
    unk4: int
    cpuid: AmdCpuId
    unk5: int
    unk6: int
    unk7: int
    unk8: int
    unk9: int
    unk10: int

    @staticmethod
    def from_bytes(buf: bytes) -> "PatchHeader":
        if len(buf) < PatchHeader.SIZE:
            raise ValueError("not enough bytes for AMD header")
        date = PatchDate.from_bytes(buf)
        patch_level = PatchLevel.from_bytes(buf[PatchDate.SIZE:])
        rest_start = PatchDate.SIZE + PatchLevel.SIZE
        chunk = buf[rest_start:PatchHeader.SIZE]
        vals = struct.unpack(PatchHeader.FMT, chunk)
        return PatchHeader(
            date=date,
            patch_level=patch_level,
            loader_id=vals[0],
            unk0=vals[1],
            unk1=vals[2],
            unk2=vals[3],
            unk3=vals[4],
            unk4=vals[5],
            cpuid=AmdCpuId.from_ucode_signature(vals[6]),
            unk5=vals[7],
            unk6=vals[8],
            unk7=vals[9],
            unk8=vals[10],
            unk9=vals[11],
            unk10=vals[12],
        )

    def to_bytes(self) -> bytes:
        return self.date.to_bytes() + self.patch_level.to_bytes() + struct.pack(
            PatchHeader.FMT,
            self.loader_id,
            self.unk0,
            self.unk1,
            self.unk2,
            self.unk3,
            self.unk4,
            self.cpuid.ucode_signature,
            self.unk5,
            self.unk6,
            self.unk7,
            self.unk8,
            self.unk9,
            self.unk10,
        )
