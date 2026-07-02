// The QEMU sifive_u board package hard-codes RamSize to 512 MiB (its mem.go is
// tagged !linkramsize). The One-More-MAYO L1 blind sign peaks just above that,
// so we build with -tags linkramsize and override RamSize here to 1.75 GiB
// (backed by a matching DTB memory node and qemu -m 2G).
//
//go:build tamago && linkramsize

package main

import _ "unsafe"

//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x70000000
