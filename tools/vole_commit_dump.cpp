// vole_commit_dump: reference-vector generator for the optimized_bs VOLE
// commitment (ggm_forest BAVC + small_vole) underlying vole_prove_1.
//
// Compiles against the stipulated source (pq_blind_signatures
// vole/optimized_bs, staged into vole/faest-cpp-tmp), with hash.hpp overridden
// by tools/ref_hash_shim.hpp (FIPS-202 one-shot SHAKE, bit-identical to XKCP).
// Dumps seed/iv and the vole_commit outputs (u, v, corrections, check) for the
// three v1 MAYO small param sets so the Go port can be checked byte-exact.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "parameters.hpp"
#include "constants.hpp"
#include "faest_keys.hpp"
#include "vole_commit.inc"
#include "small_vole.inc"
#include "vole_check.hpp"

using namespace faest;

// vole_check is defined in vole_check.cpp (template); pull the definition in
// directly by including the .inc-style body via the header + this shim path.
// The reference splits declaration (vole_check.hpp) from the .cpp; we compile
// the .cpp alongside, so only declarations are needed here.

static uint64_t sm_state = 0x746d61796f2d7663ULL; // "tamayo-vc"
static uint64_t splitmix64()
{
    uint64_t z = (sm_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
static void rand_bytes(uint8_t* p, size_t n) { for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)(splitmix64() & 0xff); }

static bool first_case = true;
static void print_hex(const char* name, const uint8_t* p, size_t n, bool comma = true)
{
    printf("\"%s\":\"", name);
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\"%s", comma ? "," : "");
}

template <typename P> void run_case(const char* name)
{
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;
    constexpr size_t lambda_bytes = secpar_to_bytes(S);

    block_secpar<S> seed;
    block128 iv;
    uint8_t seed_b[lambda_bytes], iv_b[16];
    rand_bytes(seed_b, lambda_bytes);
    rand_bytes(iv_b, 16);
    memset(&seed, 0, sizeof(seed));
    memcpy(&seed, seed_b, lambda_bytes);
    memset(&iv, 0, sizeof(iv));
    memcpy(&iv, iv_b, 16);

    vole_block* u = (vole_block*)aligned_alloc(alignof(vole_block), CP::VOLE_COL_BLOCKS * sizeof(vole_block));
    vole_block* v = (vole_block*)aligned_alloc(alignof(vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(vole_block));
    block_secpar<S>* forest = (block_secpar<S>*)aligned_alloc(alignof(block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(block_secpar<S>));
    unsigned char* hashed_leaves = (unsigned char*)aligned_alloc(alignof(block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
    std::vector<uint8_t> commitment(CP::VOLE_COMMIT_SIZE);
    uint8_t check[CP::VOLE_COMMIT_CHECK_SIZE];

    vole_commit<P>(seed, iv, forest, hashed_leaves, u, v, commitment.data(), check);

    if (!first_case) printf(",\n");
    first_case = false;
    printf("{\"name\":\"%s\",\"secpar\":%zu,\"tau\":%zu,", name, (size_t)secpar_to_bits(S), (size_t)P::tau_v);
    printf("\"vole_col_blocks\":%zu,\"vole_rows\":%zu,\"vole_commit_size\":%zu,\"witness_bits\":%zu,",
           (size_t)CP::VOLE_COL_BLOCKS, (size_t)CP::VOLE_ROWS, (size_t)CP::VOLE_COMMIT_SIZE,
           (size_t)P::OWF_CONSTS::WITNESS_BITS);
    printf("\"min_k\":%zu,\"max_k\":%zu,\"num_max_k\":%zu,\"num_min_k\":%zu,",
           (size_t)CP::VEC_COM::MIN_K, (size_t)CP::VEC_COM::MAX_K,
           (size_t)CP::VEC_COM::NUM_MAX_K, (size_t)CP::VEC_COM::NUM_MIN_K);
    print_hex("seed", seed_b, lambda_bytes);
    print_hex("iv", iv_b, 16);
    print_hex("u", (uint8_t*)u, CP::VOLE_COL_BLOCKS * sizeof(vole_block));
    print_hex("v", (uint8_t*)v, P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(vole_block));
    print_hex("commitment", commitment.data(), commitment.size());
    print_hex("check", check, CP::VOLE_COMMIT_CHECK_SIZE);

    // vole_check_sender on a fixed challenge: dump the proof (u_tilde) output
    // and a finalized copy of the transcript hasher (the D-matrix hashes it
    // absorbs, which feed chal2).
    const size_t vc_chal = CP::VOLE_CHECK::CHALLENGE_BYTES;
    std::vector<uint8_t> challenge(vc_chal);
    rand_bytes(challenge.data(), vc_chal);
    std::vector<uint8_t> vc_proof(CP::VOLE_CHECK::PROOF_BYTES);
    hash_state vc_hasher;
    vc_hasher.init(S);
    vole_check_sender<P>(u, v, challenge.data(), vc_proof.data(), vc_hasher);
    uint8_t vc_hash[2 * lambda_bytes];
    vc_hasher.finalize(vc_hash, 2 * lambda_bytes);
    printf("\"vole_check_challenge_bytes\":%zu,", vc_chal);
    print_hex("vole_check_challenge", challenge.data(), vc_chal);
    print_hex("vole_check_proof", vc_proof.data(), vc_proof.size());
    print_hex("vole_check_hash", vc_hash, 2 * lambda_bytes);

    // transpose_secpar output, computed with a naive bit transpose (identical
    // permutation, no AVX2 template): v is lambda columns each VOLE_COL_STRIDE
    // bytes apart; macs[row] is a lambda-bit element whose bit c is column c's
    // bit `row`. Dump the first (WITNESS_BITS + lambda) rows the QS consumes.
    size_t rows_out = P::OWF_CONSTS::WITNESS_BITS + lambda_bytes * 8;
    const uint8_t* vb = (const uint8_t*)v;
    std::vector<uint8_t> macs(rows_out * lambda_bytes, 0);
    for (size_t c = 0; c < (size_t)lambda_bytes * 8; ++c)
    {
        const uint8_t* col = vb + c * CP::VOLE_COL_STRIDE;
        for (size_t r = 0; r < rows_out; ++r)
        {
            uint8_t bit = (col[r / 8] >> (r % 8)) & 1;
            macs[r * lambda_bytes + c / 8] |= bit << (c % 8);
        }
    }
    printf("\"transpose_rows\":%zu,", rows_out);
    print_hex("macs", macs.data(), macs.size(), false);
    printf("}");

    free(u); free(v); free(forest); free(hashed_leaves);
}

int main()
{
    printf("[\n");
    run_case<v1::mayo_128_s>("mayo_128_s");
    run_case<v1::mayo_192_s>("mayo_192_s");
    run_case<v1::mayo_256_s>("mayo_256_s");
    printf("\n]\n");
    return 0;
}
