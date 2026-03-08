#!/usr/bin/env python

import struct
from dataclasses import dataclass

def _weird_hex_as_dec(x: int) -> int:
    return int(f"{x:x}", 10)


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
    processor_rev_id: int

    @property
    def cpu_family(self) -> int:
        return 0xf + (self.processor_rev_id >> 12)

    @property
    def cpu_model(self) -> int:
        return (self.processor_rev_id >> 4) & 0xf
    
    @property
    def cpu_stepping(self) -> int:
        return self.processor_rev_id & 0xf

    @property
    def cpuid_str(self) -> str:
        hi = (self.processor_rev_id >> 8) & 0xFF
        lo = self.processor_rev_id & 0xFF
        return f"00{hi:02X}0F{lo:02X}"

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
            processor_rev_id=vals[10]
        )
