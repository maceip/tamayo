#!/usr/bin/env python3
"""generate a minimal riscv64 bios for qemu -bios that jumps to the ELF entry
point of the given kernel.

the tamago boot flow on qemu sifive_u needs a firmware stage at the DRAM base
(0x80000000) that jumps to the kernel's _rt0_riscv64_tamago. a prebuilt
bios.bin hardcodes that address, which silently breaks whenever the kernel is
relinked and the entry symbol moves (the bios then jumps into the middle of
whatever code now lives at the stale address). this script reads e_entry from
the kernel ELF and emits a 24-byte flat binary:

    auipc t0, 0
    ld    t0, 16(t0)
    jr    t0
    nop
    .quad e_entry

usage: mkbios.py <kernel-elf> <bios-out>
"""

import struct
import sys


def main() -> None:
    kernel, out = sys.argv[1], sys.argv[2]
    with open(kernel, "rb") as f:
        head = f.read(0x20)
    if head[:4] != b"\x7fELF":
        sys.exit(f"{kernel}: not an ELF")
    entry = struct.unpack_from("<Q", head, 0x18)[0]

    code = struct.pack(
        "<4I",
        0x00000297,  # auipc t0, 0
        0x0102B283,  # ld    t0, 16(t0)
        0x00028067,  # jr    t0
        0x00000013,  # nop
    ) + struct.pack("<Q", entry)

    with open(out, "wb") as f:
        f.write(code)
    print(f"bios: jump to {entry:#x} ({out})")


if __name__ == "__main__":
    main()
