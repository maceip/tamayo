// full_proof_dump: end-to-end reference-vector generator for the One-More-MAYO
// VOLE proof. Runs the stipulated vole_prove_1 -> vole_prove_2 -> vole_verify
// (optimized_bs/faest.inc) deterministically and dumps packed sk/pk,
// r_additional and the full proof bytes, plus the proof-layout constants, so the
// Go transcript can be checked byte-exact in both directions.
//
// hash.hpp -> tools/ref_hash_shim.hpp (FIPS-202 SHAKE);
// transpose_secpar.hpp -> tools/ref_transpose_shim.hpp (naive bit transpose).

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "parameters.hpp"
#include "constants.hpp"
#include "faest_keys.inc"
#include "vole_commit.inc"
#include "small_vole.inc"
#include "owf_proof.inc"
#include "faest.inc"
#include "test/test.hpp"

using namespace faest;

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
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    block128 iv_pre;
    vole_block* u = (vole_block*)aligned_alloc(alignof(vole_block), CP::VOLE_COL_BLOCKS * sizeof(vole_block));
    vole_block* v = (vole_block*)aligned_alloc(alignof(vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(vole_block));
    block_secpar<S>* forest = (block_secpar<S>*)aligned_alloc(alignof(block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(block_secpar<S>));
    unsigned char* hashed_leaves = (unsigned char*)aligned_alloc(alignof(block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);

    std::vector<uint8_t> proof((size_t)VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32, 0xff);

    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_pre, hashed_leaves, proof.data(),
                    NULL, 0, r_additional.data());

    std::vector<uint8_t> pk_packed(VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
    std::vector<uint8_t> sk_packed(VOLEMAYO_SECRET_SIZE_BYTES<S>);
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_pre, sizeof(iv_pre), forest,
                    hashed_leaves, pk_packed.data(), sk_packed.data(), r_additional.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(),
                              pk_packed.size(), r_additional.data());
    if (!ret)
    {
        fprintf(stderr, "FATAL: reference vole_verify failed (%s)\n", name);
        exit(1);
    }

    if (!first_case) printf(",\n");
    first_case = false;
    printf("{\"name\":\"%s\",\"secpar\":%zu,", name, (size_t)secpar_to_bits(S));
    printf("\"proof_bytes\":%zu,\"vole_commit_size\":%zu,\"vole_check_proof_bytes\":%zu,",
           (size_t)VOLE_PROOF_BYTES<P>, (size_t)CP::VOLE_COMMIT_SIZE, (size_t)CP::VOLE_CHECK::PROOF_BYTES);
    printf("\"witness_bits\":%zu,\"qs_proof_bytes\":%zu,\"open_size\":%zu,\"r_bytes\":%zu,",
           (size_t)OC::WITNESS_BITS, (size_t)CP::QS::PROOF_BYTES, (size_t)P::bavc_t::OPEN_SIZE,
           (size_t)VOLEMAYO_R_BYTES<S>);
    print_hex("r_additional", r_additional.data(), 32);
    print_hex("pk", pk_packed.data(), pk_packed.size());
    print_hex("sk", sk_packed.data(), sk_packed.size());
    print_hex("proof", proof.data(), proof.size(), false);
    printf("}");

    free(u); free(v); free(forest); free(hashed_leaves);
}

int main()
{
    srand(1);
    printf("[\n");
    run_case<v1::mayo_128_s>("mayo_128_s");
    run_case<v1::mayo_192_s>("mayo_192_s");
    run_case<v1::mayo_256_s>("mayo_256_s");
    printf("\n]\n");
    return 0;
}
