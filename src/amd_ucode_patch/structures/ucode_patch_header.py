#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from dataclasses import dataclass
from amd_cpuid import AmdCpuId

def _weird_hex_as_dec(x: int) -> int:
    return int(f"{x:x}", 10)


def _dec_as_weird_hex(x: int) -> int:
    return int(str(x), 16)


@dataclass
class UcodePatchHeader:
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
    FMT = "<HBB I HBB I II H BBBBBB"
    SIZE = struct.calcsize(FMT)

    year: int
    day: int
    month: int
    update_revision: int
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
    def from_bytes(buf: bytes) -> "UcodePatchHeader":
        if len(buf) < UcodePatchHeader.SIZE:
            raise ValueError("not enough bytes for AMD header")
        chunk = buf[0:UcodePatchHeader.SIZE]
        vals = struct.unpack(UcodePatchHeader.FMT, chunk)
        return UcodePatchHeader(
            year=_weird_hex_as_dec(vals[0]),
            day=_weird_hex_as_dec(vals[1]),
            month=_weird_hex_as_dec(vals[2]),
            update_revision=vals[3],
            loader_id=vals[4],
            unk0=vals[5],
            unk1=vals[6],
            unk2=vals[7],
            unk3=vals[8],
            unk4=vals[9],
            cpuid=AmdCpuId.from_ucode_signature(vals[10]),
            unk5=vals[11],
            unk6=vals[12],
            unk7=vals[13],
            unk8=vals[14],
            unk9=vals[15],
            unk10=vals[16],
        )

    def to_bytes(self) -> bytes:
        return struct.pack(
            UcodePatchHeader.FMT,
            _dec_as_weird_hex(self.year),
            _dec_as_weird_hex(self.day),
            _dec_as_weird_hex(self.month),
            self.update_revision,
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
