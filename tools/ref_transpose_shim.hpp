// Drop-in replacement for transpose_secpar.hpp used only to build the tamayo
// full-proof dumper with plain g++ (the real avx2/transpose_secpar_impl.hpp is
// a heavy SIMD template that OOMs a t3.large under -march=native x3 secpars).
// transpose_secpar is a pure GF(2) bit permutation, so this naive version is
// byte-identical to the reference; the tamayo Go transpose is already verified
// byte-exact against it.
#ifndef TRANSPOSE_SECPAR_HPP
#define TRANSPOSE_SECPAR_HPP

#include "parameters.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace faest
{

// Column-major (rows x secpar bits, columns `stride` bytes apart) -> row-major
// (rows elements of secpar_to_bytes(S) bytes). output[r] bit c = column c bit r.
template <secpar S>
void transpose_secpar(const void* input, void* output, size_t stride, size_t rows)
{
    constexpr size_t lb = secpar_to_bytes(S);
    const uint8_t* in = (const uint8_t*)input;
    uint8_t* out = (uint8_t*)output;
    memset(out, 0, rows * lb);
    for (size_t c = 0; c < lb * 8; ++c)
    {
        const uint8_t* col = in + c * stride;
        for (size_t r = 0; r < rows; ++r)
        {
            uint8_t bit = (col[r / 8] >> (r % 8)) & 1;
            out[r * lb + c / 8] |= bit << (c % 8);
        }
    }
}

} // namespace faest

#endif
