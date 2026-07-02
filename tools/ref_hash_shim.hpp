// Drop-in replacement for pq_blind_signatures vole/faest-cpp-tmp/hash.hpp used
// only to build the tamayo reference-vector dumpers with plain g++ (no XKCP /
// meson subproject). It backs hash_state / hash_state_x4 with the box's
// common/fips202.c one-shot SHAKE (buffer-then-squeeze), which is bit-identical
// to the reference's XKCP incremental SHAKE and to Go crypto/sha3 (all FIPS-202).
// A green Go-vs-dumper KAT therefore certifies the substitution is faithful.
#ifndef HASH_HPP
#define HASH_HPP

#include "block.hpp"
#include <cinttypes>
#include <cstddef>
#include <cstring>
#include <vector>

// The box's common/fips202.h only declares the one-shot shake128 (defined) and
// shake256 (declared but NOT defined in the object). We instead use the
// incremental API, which is defined in fips202.c but not in the header, so we
// declare it (and its ctx type) here to match fips202.c exactly.
extern "C" {
typedef struct { uint64_t* ctx; } shake128incctx;
typedef struct { uint64_t* ctx; } shake256incctx;
void shake128_inc_init(shake128incctx* state);
void shake128_inc_absorb(shake128incctx* state, const uint8_t* input, size_t inlen);
void shake128_inc_finalize(shake128incctx* state);
void shake128_inc_squeeze(uint8_t* output, size_t outlen, shake128incctx* state);
void shake128_inc_ctx_release(shake128incctx* state);
void shake256_inc_init(shake256incctx* state);
void shake256_inc_absorb(shake256incctx* state, const uint8_t* input, size_t inlen);
void shake256_inc_finalize(shake256incctx* state);
void shake256_inc_squeeze(uint8_t* output, size_t outlen, shake256incctx* state);
void shake256_inc_ctx_release(shake256incctx* state);
}

namespace faest_shim
{
// One-shot SHAKE via the box's incremental FIPS-202 API. Bit-identical to XKCP
// and Go crypto/sha3 (all FIPS-202).
inline void shake128_oneshot(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    shake128incctx st;
    shake128_inc_init(&st);
    shake128_inc_absorb(&st, in, inlen);
    shake128_inc_finalize(&st);
    shake128_inc_squeeze(out, outlen, &st);
    shake128_inc_ctx_release(&st);
}
inline void shake256_oneshot(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, in, inlen);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, outlen, &st);
    shake256_inc_ctx_release(&st);
}
} // namespace faest_shim

namespace faest
{

struct hash_state
{
    std::vector<uint8_t> buf;
    bool s256 = false;

    inline int init(secpar s)
    {
        buf.clear();
        s256 = secpar_to_bits(s) > 128;
        return 0;
    }

    inline int update(const void* input, size_t bytes)
    {
        const uint8_t* p = (const uint8_t*)input;
        buf.insert(buf.end(), p, p + bytes);
        return 0;
    }

    inline int update_byte(uint8_t b) { return this->update(&b, 1); }

    inline int finalize(void* digest, size_t bytes)
    {
        if (s256)
            faest_shim::shake256_oneshot((uint8_t*)digest, bytes, buf.data(), buf.size());
        else
            faest_shim::shake128_oneshot((uint8_t*)digest, bytes, buf.data(), buf.size());
        return 0;
    }
};

struct hash_state_x4
{
    hash_state h[4];

    inline void init(secpar s)
    {
        for (int i = 0; i < 4; ++i)
            h[i].init(s);
    }

    inline void update(const void** data, size_t size)
    {
        for (int i = 0; i < 4; ++i)
            h[i].update(data[i], size);
    }

    inline void update_4(const void* d0, const void* d1, const void* d2, const void* d3, size_t size)
    {
        const void* d[4] = {d0, d1, d2, d3};
        this->update(d, size);
    }

    inline void update_1(const void* data, size_t size) { this->update_4(data, data, data, data, size); }

    inline void update_1_byte(uint8_t b) { this->update_1(&b, 1); }

    inline void init_prefix(secpar s, const uint8_t prefix)
    {
        this->init(s);
        this->update_1(&prefix, sizeof(prefix));
    }

    inline void finalize(void** buffer, size_t buflen)
    {
        for (int i = 0; i < 4; ++i)
            h[i].finalize(buffer[i], buflen);
    }

    inline void finalize_4(void* b0, void* b1, void* b2, void* b3, size_t buflen)
    {
        void* b[4] = {b0, b1, b2, b3};
        this->finalize(b, buflen);
    }
};

template <secpar S>
inline void shake_prg_impl(const block_secpar<S>* __restrict__ keys, const block128& iv,
                           const uint32_t& tweak, size_t num_keys, size_t num_bytes,
                           uint8_t* __restrict__ output)
{
    size_t i;
    for (i = 0; i + 4 <= num_keys; i += 4)
    {
        const void* key_arr[4];
        void* output_arr[4];
        for (size_t j = 0; j < 4; ++j)
        {
            key_arr[j] = &keys[i + j];
            output_arr[j] = output + (i + j) * num_bytes;
        }

        hash_state_x4 hasher;
        hasher.init(S);
        hasher.update(key_arr, sizeof(keys[i]));
        hasher.update_1(&iv, sizeof(iv));
        hasher.update_1(&tweak, sizeof(tweak));
        hasher.update_1_byte(0);
        hasher.finalize(output_arr, num_bytes);
    }

    for (; i < num_keys; ++i)
    {
        hash_state hasher;
        hasher.init(S);
        hasher.update(&keys[i], sizeof(keys[i]));
        hasher.update(&iv, sizeof(iv));
        hasher.update(&tweak, sizeof(tweak));
        hasher.update_byte(0);
        hasher.finalize(output + i * num_bytes, num_bytes);
    }
}

} // namespace faest

#endif
