// hash.hpp replacement for the combined blind-loop dumper, which links MAYO-C's
// fips202 (providing one-shot shake128/shake256). Backs the vole hash_state /
// hash_state_x4 with those one-shot calls; bit-identical to XKCP and Go
// crypto/sha3 (all FIPS-202).
#ifndef HASH_HPP
#define HASH_HPP

#include "block.hpp"
#include <cinttypes>
#include <cstddef>
#include <cstring>
#include <vector>

extern "C" {
int shake128(unsigned char* output, size_t outlen, const unsigned char* input, size_t inlen);
int shake256(unsigned char* output, size_t outlen, const unsigned char* input, size_t inlen);
}

namespace faest
{

struct hash_state
{
    std::vector<uint8_t> buf;
    bool s256 = false;

    inline int init(secpar s) { buf.clear(); s256 = secpar_to_bits(s) > 128; return 0; }
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
            shake256((unsigned char*)digest, bytes, buf.data(), buf.size());
        else
            shake128((unsigned char*)digest, bytes, buf.data(), buf.size());
        return 0;
    }
};

struct hash_state_x4
{
    hash_state h[4];
    inline void init(secpar s) { for (int i = 0; i < 4; ++i) h[i].init(s); }
    inline void update(const void** data, size_t size) { for (int i = 0; i < 4; ++i) h[i].update(data[i], size); }
    inline void update_4(const void* d0, const void* d1, const void* d2, const void* d3, size_t size)
    { const void* d[4] = {d0, d1, d2, d3}; this->update(d, size); }
    inline void update_1(const void* data, size_t size) { this->update_4(data, data, data, data, size); }
    inline void update_1_byte(uint8_t b) { this->update_1(&b, 1); }
    inline void init_prefix(secpar s, const uint8_t prefix) { this->init(s); this->update_1(&prefix, sizeof(prefix)); }
    inline void finalize(void** buffer, size_t buflen) { for (int i = 0; i < 4; ++i) h[i].finalize(buffer[i], buflen); }
    inline void finalize_4(void* b0, void* b1, void* b2, void* b3, size_t buflen)
    { void* b[4] = {b0, b1, b2, b3}; this->finalize(b, buflen); }
};

template <secpar S>
inline void shake_prg_impl(const block_secpar<S>* __restrict__ keys, const block128& iv,
                           const uint32_t& tweak, size_t num_keys, size_t num_bytes,
                           uint8_t* __restrict__ output)
{
    for (size_t i = 0; i < num_keys; ++i)
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
