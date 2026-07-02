package faest

import (
	"encoding/binary"
	"math/bits"
)

// Fixsliced (32-bit, LUT-free) Rijndael, transpiled from faest-rs
// src/rijndael_32.rs (itself adapted from the RustCrypto aes fixslice backend,
// original C by Alexandre Adomnicai). Supports every key-column count nk and
// block-column count bc in {4,6,8}, covering AES-128/192/256 and the wider
// Rijndael-192/256 blocks used by FAEST-EM. This is the clear cipher used to
// derive the FAEST witness.

var rconTable = [30]byte{
	1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53,
	106, 212, 179, 125, 250, 239, 197, 145,
}

const (
	rijM0 uint32 = 0x55555555
	rijM1 uint32 = 0x33333333
	rijM2 uint32 = 0x0f0f0f0f
)

func rotr32(x uint32, k int) uint32 { return bits.RotateLeft32(x, -k) }

// ror_distance(rows,cols) = (rows<<3)+(cols<<1); rotate_rows_1/2 use cols=0.
func rotateRows1(x uint32) uint32 { return rotr32(x, 8) }
func rotateRows2(x uint32) uint32 { return rotr32(x, 16) }

func deltaSwap1(a, shift, mask uint32) uint32 {
	t := (a ^ (a >> shift)) & mask
	return a ^ t ^ (t << shift)
}

func deltaSwap2(a, b, shift, mask uint32) (uint32, uint32) {
	t := (a ^ (b >> shift)) & mask
	return a ^ t, b ^ (t << shift)
}

// subBytes is the bitsliced AES S-box (Boyar-Peralta-Calik), with the four NOTs
// deferred to subBytesNots. Operates on an 8-word bitsliced state.
func subBytes(st []uint32) {
	u7 := st[0]
	u6 := st[1]
	u5 := st[2]
	u4 := st[3]
	u3 := st[4]
	u2 := st[5]
	u1 := st[6]
	u0 := st[7]

	y14 := u3 ^ u5
	y13 := u0 ^ u6
	y12 := y13 ^ y14
	t1 := u4 ^ y12
	y15 := t1 ^ u5
	t2 := y12 & y15
	y6 := y15 ^ u7
	y20 := t1 ^ u1
	y9 := u0 ^ u3
	y11 := y20 ^ y9
	t12 := y9 & y11
	y7 := u7 ^ y11
	y8 := u0 ^ u5
	t0 := u1 ^ u2
	y10 := y15 ^ t0
	y17 := y10 ^ y11
	t13 := y14 & y17
	t14 := t13 ^ t12
	y19 := y10 ^ y8
	t15 := y8 & y10
	t16 := t15 ^ t12
	y16 := t0 ^ y11
	y21 := y13 ^ y16
	t7 := y13 & y16
	y18 := u0 ^ y16
	y1 := t0 ^ u7
	y4 := y1 ^ u3
	t5 := y4 & u7
	t6 := t5 ^ t2
	t18 := t6 ^ t16
	t22 := t18 ^ y19
	y2 := y1 ^ u0
	t10 := y2 & y7
	t11 := t10 ^ t7
	t20 := t11 ^ t16
	t24 := t20 ^ y18
	y5 := y1 ^ u6
	t8 := y5 & y1
	t9 := t8 ^ t7
	t19 := t9 ^ t14
	t23 := t19 ^ y21
	y3 := y5 ^ y8
	t3 := y3 & y6
	t4 := t3 ^ t2
	t17 := t4 ^ y20
	t21 := t17 ^ t14
	t26 := t21 & t23
	t27 := t24 ^ t26
	t31 := t22 ^ t26
	t25 := t21 ^ t22
	t28 := t25 & t27
	t29 := t28 ^ t22
	z14 := t29 & y2
	z5 := t29 & y7
	t30 := t23 ^ t24
	t32 := t31 & t30
	t33 := t32 ^ t24
	t35 := t27 ^ t33
	t36 := t24 & t35
	t38 := t27 ^ t36
	t39 := t29 & t38
	t40 := t25 ^ t39
	t43 := t29 ^ t40
	z3 := t43 & y16
	tc12 := z3 ^ z5
	z12 := t43 & y13
	z13 := t40 & y5
	z4 := t40 & y1
	tc6 := z3 ^ z4
	t34 := t23 ^ t33
	t37 := t36 ^ t34
	t41 := t40 ^ t37
	z8 := t41 & y10
	z17 := t41 & y8
	t44 := t33 ^ t37
	z0 := t44 & y15
	z9 := t44 & y12
	z10 := t37 & y3
	z1 := t37 & y6
	tc5 := z1 ^ z0
	tc11 := tc6 ^ tc5
	z11 := t33 & y4
	t42 := t29 ^ t33
	t45 := t42 ^ t41
	z7 := t45 & y17
	tc8 := z7 ^ tc6
	z16 := t45 & y14
	z6 := t42 & y11
	tc16 := z6 ^ tc8
	z15 := t42 & y9
	tc20 := z15 ^ tc16
	tc1 := z15 ^ z16
	tc2 := z10 ^ tc1
	tc21 := tc2 ^ z11
	tc3 := z9 ^ tc2
	s0 := tc3 ^ tc16
	s3 := tc3 ^ tc11
	s1 := s3 ^ tc16
	tc13 := z13 ^ tc1
	z2 := t33 & u7
	tc4 := z0 ^ z2
	tc7 := z12 ^ tc4
	tc9 := z8 ^ tc7
	tc10 := tc8 ^ tc9
	tc17 := z14 ^ tc10
	s5 := tc21 ^ tc17
	tc26 := tc17 ^ tc20
	s2 := tc26 ^ z17
	tc14 := tc4 ^ tc12
	tc18 := tc13 ^ tc14
	s6 := tc10 ^ tc18
	s7 := z12 ^ tc18
	s4 := tc14 ^ s3

	st[0] = s7
	st[1] = s6
	st[2] = s5
	st[3] = s4
	st[4] = s3
	st[5] = s2
	st[6] = s1
	st[7] = s0
}

func subBytesNots(st []uint32) {
	st[0] ^= 0xffffffff
	st[1] ^= 0xffffffff
	st[5] ^= 0xffffffff
	st[6] ^= 0xffffffff
}

func mixColumns0(st []uint32) {
	a0, a1, a2, a3, a4, a5, a6, a7 := st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]
	b0 := rotateRows1(a0)
	b1 := rotateRows1(a1)
	b2 := rotateRows1(a2)
	b3 := rotateRows1(a3)
	b4 := rotateRows1(a4)
	b5 := rotateRows1(a5)
	b6 := rotateRows1(a6)
	b7 := rotateRows1(a7)
	c0 := a0 ^ b0
	c1 := a1 ^ b1
	c2 := a2 ^ b2
	c3 := a3 ^ b3
	c4 := a4 ^ b4
	c5 := a5 ^ b5
	c6 := a6 ^ b6
	c7 := a7 ^ b7
	st[0] = b0 ^ c7 ^ rotateRows2(c0)
	st[1] = b1 ^ c0 ^ c7 ^ rotateRows2(c1)
	st[2] = b2 ^ c1 ^ rotateRows2(c2)
	st[3] = b3 ^ c2 ^ c7 ^ rotateRows2(c3)
	st[4] = b4 ^ c3 ^ c7 ^ rotateRows2(c4)
	st[5] = b5 ^ c4 ^ rotateRows2(c5)
	st[6] = b6 ^ c5 ^ rotateRows2(c6)
	st[7] = b7 ^ c6 ^ rotateRows2(c7)
}

func rijndaelShiftRows1(st []uint32, bc int) {
	for i := range st {
		x := st[i]
		switch bc {
		case 4:
			x = deltaSwap1(x, 4, 0x0c0f0300)
			x = deltaSwap1(x, 2, 0x33003300)
		case 6:
			x = deltaSwap1(x, 6, 0x01000000)
			x = deltaSwap1(x, 3, 0x000a0200)
			x = deltaSwap1(x, 2, 0x00003300)
			x = deltaSwap1(x, 1, 0x0a050400)
		default:
			x = deltaSwap1(x, 4, 0x000c0300)
			x = deltaSwap1(x, 2, 0x00333300)
			x = deltaSwap1(x, 1, 0x55544000)
		}
		st[i] = x
	}
}

func xorColumns(rkeys []uint32, offset, nk int) {
	switch nk {
	case 4:
		for i := 0; i < 8; i++ {
			o := offset + i
			rk := rkeys[o-8] ^ (0x03030303 & rotr32(rkeys[o], 14))
			rkeys[o] = rk ^ (0xfcfcfcfc & (rk << 2)) ^ (0xf0f0f0f0 & (rk << 4)) ^ (0xc0c0c0c0 & (rk << 6))
		}
	case 6:
		for i := 0; i < 8; i++ {
			o := offset + i
			rk := rkeys[o-8] ^ (0x01010101 & rotr32(rkeys[o], 11))
			rkeys[o] = rk ^
				(0x5c5c5c5c & (rk << 2)) ^
				(0x02020202 & (rk >> 5)) ^
				(0x50505050 & (rk << 4)) ^
				(0x0a0a0a0a & (rk >> 3)) ^
				(0x0a0a0a0a & (rk << 1)) ^
				(0x0a0a0a0a & (rk >> 1)) ^
				(0x08080808 & (rk << 3)) ^
				(0x40404040 & (rk << 6))
		}
	default:
		var temp [8]uint32
		for i := 0; i < 8; i++ {
			o := offset + i
			rk := rkeys[o-8] ^ (0x01010101 & rotr32(rkeys[o], 15))
			rkeys[o] = rk ^ (0x54545454 & (rk << 2)) ^ (0x50505050 & (rk << 4)) ^ (0x40404040 & (rk << 6))
			temp[i] = rkeys[o]
		}
		subBytes(temp[:])
		subBytesNots(temp[:])
		for i := 0; i < 8; i++ {
			o := offset + i
			rk := rkeys[o] ^ (temp[i%8]&0x40404040)>>5
			rkeys[o] = rk ^ (0xa8a8a8a8 & (rk << 2)) ^ (0xa0a0a0a0 & (rk << 4)) ^ (0x80808080 & (rk << 6))
		}
	}
}

func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// bitslice packs input0 (16 bytes) and input1 (0, 8, or 16 bytes) into an 8-word
// bitsliced state.
func bitslice(output []uint32, input0, input1 []byte) {
	t0 := le32(input0[0x00:0x04])
	t2 := le32(input0[0x04:0x08])
	t4 := le32(input0[0x08:0x0c])
	t6 := le32(input0[0x0c:0x10])
	var t1, t3, t5, t7 uint32
	if len(input1) != 0 {
		t1 = le32(input1[0x00:0x04])
		t3 = le32(input1[0x04:0x08])
	}
	if len(input1) > 8 {
		t5 = le32(input1[0x08:0x0c])
		t7 = le32(input1[0x0c:0x10])
	}

	t1, t0 = deltaSwap2(t1, t0, 1, rijM0)
	t3, t2 = deltaSwap2(t3, t2, 1, rijM0)
	t5, t4 = deltaSwap2(t5, t4, 1, rijM0)
	t7, t6 = deltaSwap2(t7, t6, 1, rijM0)

	t2, t0 = deltaSwap2(t2, t0, 2, rijM1)
	t3, t1 = deltaSwap2(t3, t1, 2, rijM1)
	t6, t4 = deltaSwap2(t6, t4, 2, rijM1)
	t7, t5 = deltaSwap2(t7, t5, 2, rijM1)

	t4, t0 = deltaSwap2(t4, t0, 4, rijM2)
	t5, t1 = deltaSwap2(t5, t1, 4, rijM2)
	t6, t2 = deltaSwap2(t6, t2, 4, rijM2)
	t7, t3 = deltaSwap2(t7, t3, 4, rijM2)

	output[0] = t0
	output[1] = t1
	output[2] = t2
	output[3] = t3
	output[4] = t4
	output[5] = t5
	output[6] = t6
	output[7] = t7
}

// invBitslice un-bitslices an 8-word state into two 16-byte blocks.
func invBitslice(input []uint32) [2][16]byte {
	t0, t1, t2, t3 := input[0], input[1], input[2], input[3]
	t4, t5, t6, t7 := input[4], input[5], input[6], input[7]

	t1, t0 = deltaSwap2(t1, t0, 1, rijM0)
	t3, t2 = deltaSwap2(t3, t2, 1, rijM0)
	t5, t4 = deltaSwap2(t5, t4, 1, rijM0)
	t7, t6 = deltaSwap2(t7, t6, 1, rijM0)

	t2, t0 = deltaSwap2(t2, t0, 2, rijM1)
	t3, t1 = deltaSwap2(t3, t1, 2, rijM1)
	t6, t4 = deltaSwap2(t6, t4, 2, rijM1)
	t7, t5 = deltaSwap2(t7, t5, 2, rijM1)

	t4, t0 = deltaSwap2(t4, t0, 4, rijM2)
	t5, t1 = deltaSwap2(t5, t1, 4, rijM2)
	t6, t2 = deltaSwap2(t6, t2, 4, rijM2)
	t7, t3 = deltaSwap2(t7, t3, 4, rijM2)

	var out [2][16]byte
	binary.LittleEndian.PutUint32(out[0][0x00:0x04], t0)
	binary.LittleEndian.PutUint32(out[0][0x04:0x08], t2)
	binary.LittleEndian.PutUint32(out[0][0x08:0x0c], t4)
	binary.LittleEndian.PutUint32(out[0][0x0c:0x10], t6)
	binary.LittleEndian.PutUint32(out[1][0x00:0x04], t1)
	binary.LittleEndian.PutUint32(out[1][0x04:0x08], t3)
	binary.LittleEndian.PutUint32(out[1][0x08:0x0c], t5)
	binary.LittleEndian.PutUint32(out[1][0x0c:0x10], t7)
	return out
}

func rijndaelAddRoundKey(st, rkey []uint32) {
	for i := range st {
		st[i] ^= rkey[i]
	}
}

func divCeil(a, b int) int { return (a + b - 1) / b }

// rijndaelKeyScheduleUnbitsliced expands the key into the unbitsliced,
// padded byte layout used by rijndaelKeySchedule.
func rijndaelKeyScheduleUnbitsliced(key []byte, nst, nk, r, ske int) []byte {
	rkeys := make([]uint32, divCeil(nst, nk)*8*(r+1)+8)

	var in1 []byte
	if len(key) > 16 {
		in1 = key[16:]
	}
	bitslice(rkeys[:8], key[:16], in1)

	rkOff := 0
	for _, rcon := range rconTable[:ske/4] {
		copy(rkeys[rkOff+8:rkOff+16], rkeys[rkOff:rkOff+8])
		rkOff += 8
		subBytes(rkeys[rkOff : rkOff+8])
		subBytesNots(rkeys[rkOff : rkOff+8])

		ind := nk * 4
		var rcon0, rcon1 [16]byte
		rcon0[13] = rcon * byte(1-ind/17)
		rcon1[5] = byte(uint16(rcon) * uint16((ind/8)%2))
		rcon1[13] = rcon * byte(ind/32)
		var bsRcon [8]uint32
		bitslice(bsRcon[:], rcon0[:], rcon1[:])

		for j := 0; j < 8; j++ {
			rkeys[rkOff+j] ^= bsRcon[j]
		}

		xorColumns(rkeys, rkOff, nk)
	}

	var out []byte
	appendZeros := func(n int) { out = append(out, make([]byte, n)...) }

	switch nk {
	case 4:
		for i := 0; i < len(rkeys)/8; i++ {
			res := invBitslice(rkeys[i*8 : (i+1)*8])
			switch nst {
			case 4:
				out = append(out, res[0][0:16]...)
				appendZeros(16)
			case 6:
				switch i % 3 {
				case 0:
					out = append(out, res[0][0:16]...)
				case 1:
					out = append(out, res[0][0:8]...)
					appendZeros(8)
					out = append(out, res[0][8:16]...)
				default:
					out = append(out, res[0][0:16]...)
					appendZeros(8)
				}
			default:
				out = append(out, res[0][0:16]...)
			}
		}
	case 6:
		for i := 0; i < len(rkeys)/8; i++ {
			res := invBitslice(rkeys[i*8 : (i+1)*8])
			switch nst {
			case 4:
				if i%2 == 0 {
					out = append(out, res[0][0:16]...)
					appendZeros(16)
					out = append(out, res[1][0:8]...)
				} else {
					out = append(out, res[0][0:8]...)
					appendZeros(16)
					out = append(out, res[0][8:16]...)
					out = append(out, res[1][0:8]...)
					appendZeros(16)
				}
			case 6:
				out = append(out, res[0][0:16]...)
				out = append(out, res[1][0:8]...)
				appendZeros(8)
			default:
				out = append(out, res[0][0:16]...)
				out = append(out, res[1][0:8]...)
			}
		}
	default:
		for i := 0; i < len(rkeys)/8; i++ {
			res := invBitslice(rkeys[i*8 : (i+1)*8])
			switch nst {
			case 4:
				out = append(out, res[0][0:16]...)
				appendZeros(16)
				out = append(out, res[1][0:16]...)
				appendZeros(16)
			case 6:
				switch i % 3 {
				case 0:
					out = append(out, res[0][0:16]...)
					out = append(out, res[1][0:8]...)
					appendZeros(8)
					out = append(out, res[1][8:16]...)
				case 1:
					out = append(out, res[0][0:16]...)
					appendZeros(8)
					out = append(out, res[1][0:16]...)
				default:
					out = append(out, res[0][0:8]...)
					appendZeros(8)
					out = append(out, res[0][8:16]...)
					out = append(out, res[1][0:16]...)
					appendZeros(8)
				}
			default:
				out = append(out, res[0][0:16]...)
				out = append(out, res[1][0:16]...)
			}
		}
	}

	return out
}

// rijndaelKeySchedule expands the key into the fully-bitsliced round keys.
func rijndaelKeySchedule(key []byte, nst, nk, r, ske int) []uint32 {
	finalRes := rijndaelKeyScheduleUnbitsliced(key, nst, nk, r, ske)
	out := make([]uint32, len(finalRes)/4)
	for i := 0; i < len(finalRes)/32; i++ {
		bitslice(out[i*8:(i+1)*8], finalRes[32*i:32*i+16], finalRes[32*i+16:32*(i+1)])
	}
	return out
}

// rijndaelEncrypt encrypts one nst-column block held in the first bytes of input
// (padded to 32 bytes), returning two 16-byte output blocks.
func rijndaelEncrypt(rkeys []uint32, input []byte, nst, r int) [2][16]byte {
	state := make([]uint32, 8)
	bitslice(state, input[:16], input[16:32])
	rijndaelAddRoundKey(state, rkeys[:8])

	for off := 8; off < 8*r; off += 8 {
		subBytes(state)
		subBytesNots(state)
		rijndaelShiftRows1(state, nst)
		mixColumns0(state)
		rijndaelAddRoundKey(state, rkeys[off:off+8])
	}

	subBytes(state)
	subBytesNots(state)
	rijndaelShiftRows1(state, nst)
	rijndaelAddRoundKey(state, rkeys[r*8:r*8+8])
	return invBitslice(state)
}
