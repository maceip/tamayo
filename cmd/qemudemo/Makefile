# On-device (QEMU sifive_u / riscv64) One-More-MAYO blind signature demo.
#
# Runs sign_1 -> sign_2 -> sign_3 -> verify on bare-metal TamaGo against the
# embedded L1 reference vector (tools/blind_loop_dump.cpp output) and prints
# whether the device reproduces the reference blinded message, preimage and
# proof byte-for-byte and accepts.
#
# Requires the TamaGo toolchain (tamago-go), qemu-system-riscv64, dtc, and the
# tamago sifive_u OpenSBI bios.bin. Set TAMAGO to the tamago `go` binary.

TAMAGO ?= go
APP    := qemudemo
TEXT_START := 0x80010000

GOENV := GOOS=tamago GOARCH=riscv64 GOOSPKG=github.com/usbarmory/tamago
GOFLAGS := -tags sifive_u,gvisor,semihosting,linkramsize -trimpath \
           -ldflags "-s -w -T $(TEXT_START) -R 0x1000"

TGDIR := $(shell $(TAMAGO) list -m -f '{{.Dir}}' github.com/usbarmory/tamago)
DTS   := $(TGDIR)/board/qemu/sifive_u/qemu-riscv64-sifive_u.dts
BIOS  ?= bios.bin # tamago-example/tools/bios.bin (OpenSBI for sifive_u)

QEMU ?= qemu-system-riscv64 -machine sifive_u -m 2G -nographic -monitor none \
        -semihosting -serial stdio -net none -dtb qemu2g.dtb -bios $(BIOS)

$(APP):
	$(GOENV) $(TAMAGO) build $(GOFLAGS) -o $(APP)

# 2 GiB memory node (stock sifive_u dts caps RAM at 128 MiB; the linkramsize
# override in ramsize.go raises RamSize to match).
qemu2g.dtb:
	sed 's/0x8000000>/0x80000000>/' $(DTS) > qemu2g.dts
	dtc -I dts -O dtb qemu2g.dts -o qemu2g.dtb 2>/dev/null

qemu: $(APP) qemu2g.dtb
	$(QEMU) -kernel $(APP)

clean:
	rm -f $(APP) qemu2g.dts qemu2g.dtb
