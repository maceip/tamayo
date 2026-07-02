// The QEMU sifive_u board package hard-codes RamSize to 512 MiB (its mem.go is
// tagged !linkramsize). The One-More-MAYO blind sign/verify peaks well above
// that (L1 alone exceeded 512 MiB, the L3 loop exceeded 3.75 GiB), so we build
// with -tags linkramsize and override RamSize to 15.75 GiB (backed by a
// matching DTB memory node and qemu -m 16G).
//
//go:build tamago && linkramsize

package main

import _ "unsafe"

//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x3F0000000
