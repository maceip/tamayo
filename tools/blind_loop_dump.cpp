// blind_loop_dump: authoritative reference vectors for the full One-More-MAYO
// blind signature loop (blind_sig_optimized sign_1 -> sign_2 -> sign_3 ->
// verify). Combines the C++ optimized_bs vole engine (faest.inc) with MAYO-C
// (via mayo_bridge.c). Dumps the keypair, message, r_additional and every
// intermediate (r, h, t, bsig) plus the final proof, so the Go blind path can
// be checked byte-exact and accepting.
//
// hash.hpp -> ref_hash_shim_oneshot.hpp; transpose_secpar.hpp -> naive shim.

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

extern "C" {
int shake256(unsigned char* output, size_t outlen, const unsigned char* input, size_t inlen);
void bridge_sizes(int level, size_t* cpk, size_t* csk, size_t* epk_bytes, size_t* m_bytes, size_t* sig_no_salt);
int bridge_keygen(int level, unsigned char* cpk, unsigned char* csk);
int bridge_expand_pk(int level, const unsigned char* cpk, unsigned char* epk_bytes);
int bridge_preimage(int level, const unsigned char* csk, const unsigned char* t, size_t tlen, unsigned char* bsig);
int bridge_verify_nohash(int level, const unsigned char* cpk, const unsigned char* t, size_t tlen, const unsigned char* bsig);
}

using namespace faest;

static bool first = true;
static void ph(const char* n, const uint8_t* p, size_t k, bool comma = true)
{
    printf("\"%s\":\"", n);
    for (size_t i = 0; i < k; i++) printf("%02x", p[i]);
    printf("\"%s", comma ? "," : "");
}

template <typename P> void run(int level, const char* name)
{
    using CP = P::CONSTS;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;

    size_t cpk_len, csk_len, epk_len, m_bytes, sig_no_salt;
    bridge_sizes(level, &cpk_len, &csk_len, &epk_len, &m_bytes, &sig_no_salt);

    std::vector<uint8_t> cpk(cpk_len), csk(csk_len), epk(epk_len);
    if (bridge_keygen(level, cpk.data(), csk.data()) != 0) { fprintf(stderr, "keygen %s\n", name); exit(1); }
    if (bridge_expand_pk(level, cpk.data(), epk.data()) != 0) { fprintf(stderr, "expand %s\n", name); exit(1); }

    std::vector<uint8_t> m = {'H','e','l','l','o',' ','W','o','r','l','d','!'};
    std::vector<uint8_t> r_additional(32, 0xff);

    // --- sign_1: prove_1 then t = h + r, h = SHAKE256(m || proof1) ---
    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    block128 iv_pre;
    vole_block* u = (vole_block*)aligned_alloc(alignof(vole_block), CP::VOLE_COL_BLOCKS * sizeof(vole_block));
    vole_block* vv = (vole_block*)aligned_alloc(alignof(vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(vole_block));
    block_secpar<S>* forest = (block_secpar<S>*)aligned_alloc(alignof(block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(block_secpar<S>));
    unsigned char* hashed_leaves = (unsigned char*)aligned_alloc(alignof(block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
    std::vector<uint8_t> proof((size_t)VOLE_PROOF_BYTES<P>);

    vole_prove_1<P>(chal1.data(), r.data(), u, vv, forest, &iv_pre, hashed_leaves, proof.data(),
                    NULL, 0, r_additional.data());

    size_t proof1_size = CP::VOLE_COMMIT_SIZE;
    size_t h_size = VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>;
    std::vector<uint8_t> mup1(m.size() + proof1_size);
    memcpy(mup1.data(), m.data(), m.size());
    memcpy(mup1.data() + m.size(), proof.data(), proof1_size);
    std::vector<uint8_t> h(h_size);
    shake256(h.data(), h_size, mup1.data(), mup1.size());
    std::vector<uint8_t> t(h_size);
    for (size_t i = 0; i < h_size; i++) t[i] = h[i] ^ r[i];

    // --- sign_2: MAYO preimage of t ---
    std::vector<uint8_t> bsig(sig_no_salt);
    if (bridge_preimage(level, csk.data(), t.data(), m_bytes, bsig.data()) != 0) { fprintf(stderr, "preimage %s\n", name); exit(1); }
    if (bridge_verify_nohash(level, cpk.data(), t.data(), m_bytes, bsig.data()) != 0) { fprintf(stderr, "vnh %s\n", name); exit(1); }

    // --- sign_3: prove_2 with packed_pk = epk||h, packed_sk = packed_pk||r||bsig ---
    std::vector<uint8_t> packed_pk;
    packed_pk.insert(packed_pk.end(), epk.begin(), epk.end());
    packed_pk.insert(packed_pk.end(), h.begin(), h.end());
    std::vector<uint8_t> packed_sk = packed_pk;
    packed_sk.insert(packed_sk.end(), r.begin(), r.end());
    packed_sk.insert(packed_sk.end(), bsig.begin(), bsig.end());

    vole_prove_2<P>(proof.data(), chal1.data(), u, vv, &iv_pre, sizeof(iv_pre), forest,
                    hashed_leaves, packed_pk.data(), packed_sk.data(), r_additional.data());

    bool ok = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data(),
                             packed_pk.size(), r_additional.data());
    if (!ok) { fprintf(stderr, "verify %s\n", name); exit(1); }

    if (!first) printf(",\n");
    first = false;
    printf("{\"name\":\"%s\",\"secpar\":%zu,\"proof_bytes\":%zu,\"proof1_size\":%zu,\"h_size\":%zu,\"m_bytes\":%zu,",
           name, (size_t)secpar_to_bits(S), (size_t)VOLE_PROOF_BYTES<P>, proof1_size, h_size, m_bytes);
    ph("cpk", cpk.data(), cpk.size());
    ph("csk", csk.data(), csk.size());
    ph("epk", epk.data(), epk.size());
    ph("m", m.data(), m.size());
    ph("r_additional", r_additional.data(), 32);
    ph("r", r.data(), r.size());
    ph("h", h.data(), h.size());
    ph("t", t.data(), t.size());
    ph("bsig", bsig.data(), bsig.size());
    ph("proof", proof.data(), proof.size(), false);
    printf("}");

    free(u); free(vv); free(forest); free(hashed_leaves);
}

int main()
{
    printf("[\n");
    run<v1::mayo_128_s>(1, "mayo_128_s");
    run<v1::mayo_192_s>(3, "mayo_192_s");
    run<v1::mayo_256_s>(5, "mayo_256_s");
    printf("\n]\n");
    return 0;
}
