// mayo_circuit_dump: reference-vector generator for the MAYO-eval OWF circuit
// (owf_proof.inc enc_constraints) on top of the degree-2 QuickSilver.
//
// Uses quicksilver_test_state (the reference's own harness: builds prover/verifier
// QS states from a witness via a VOLE correlation and a random challenge), runs
// owf_constraints<P,{false,true}> and then prove/verify. Dumps every input the
// Go port needs (witness incl. mask, VOLE tags/keys, delta, chal2, packed pk,
// h) and the outputs (qs proof, prover check, verifier check).

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "parameters.hpp"
#include "constants.hpp"
#include "faest_keys.inc"
#include "owf_proof.inc"
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
    constexpr size_t lambda_bytes = secpar_to_bytes(S);
    constexpr size_t max_deg = OC::QS_DEGREE; // 2

    // Build a valid keypair: random r (u_r) and random s with h = T*(s) ^ r, so
    // the constraint value is zero.
    std::vector<uint8_t> pk_packed(VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
    std::vector<uint8_t> sk_packed(VOLEMAYO_SECRET_SIZE_BYTES<S>);
    std::vector<uint8_t> u_r(VOLEMAYO_R_BYTES<S>);
    for (auto& b : u_r) b = (uint8_t)(::rand() & 0xff);
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), u_r.data());

    // Witness = r (u_r) || s. s lives in sk at PUBLIC + R_BYTES.
    const uint8_t* s_src = sk_packed.data() + VOLEMAYO_PUBLIC_SIZE_BYTES<S> + VOLEMAYO_R_BYTES<S>;
    std::vector<uint8_t> witness(VOLEMAYO_WITNESS_SIZE_BYTES<S>);
    memcpy(witness.data(), u_r.data(), VOLEMAYO_R_BYTES<S>);
    memcpy(witness.data() + VOLEMAYO_R_BYTES<S>, s_src, VOLEMAYO_S_BYTES<S>);

    const size_t witness_bits = OC::WITNESS_BITS;
    const auto delta = ::rand<block_secpar<S>>();

    quicksilver_test_state<S, max_deg> qs_test(OC::OWF_NUM_CONSTRAINTS, witness.data(),
                                               witness_bits, delta);
    auto& prover = qs_test.prover_state;
    auto& verifier = qs_test.verifier_state;

    public_key<P> pk;
    faest_unpack_public_key<P>(&pk, pk_packed.data());

    owf_constraints<P, false>(&prover, &pk, qs_test.challenge.data());
    owf_constraints<P, true>(&verifier, &pk, qs_test.challenge.data());

    uint8_t proof[(max_deg - 1) * lambda_bytes];
    uint8_t check_p[lambda_bytes], check_v[lambda_bytes];
    prover.prove(witness_bits, proof, check_p);
    verifier.verify(witness_bits, proof, check_v);
    if (memcmp(check_p, check_v, lambda_bytes) != 0)
    {
        fprintf(stderr, "FATAL: reference check mismatch (%s)\n", name);
        exit(1);
    }

    const size_t total_bits = witness_bits + (max_deg - 1) * secpar_to_bits(S);

    if (!first_case) printf(",\n");
    first_case = false;
    printf("{\"name\":\"%s\",\"secpar\":%zu,\"witness_bits\":%zu,\"num_constraints\":%zu,",
           name, (size_t)secpar_to_bits(S), witness_bits, (size_t)OC::OWF_NUM_CONSTRAINTS);
    printf("\"n\":%zu,\"m\":%zu,\"o\":%zu,\"k\":%zu,", (size_t)VOLEMAYO_N<S>, (size_t)VOLEMAYO_M<S>,
           (size_t)VOLEMAYO_O<S>, (size_t)VOLEMAYO_K<S>);
    // Dump the FULL witness incl. the (max_deg-1)*lambda mask bytes that
    // quicksilver_test_state appended (QS::prove reads the mask value).
    print_hex("witness", qs_test.witness.data(), qs_test.witness.size());
    std::vector<uint8_t> buf(total_bits * lambda_bytes);
    for (size_t i = 0; i < total_bits; ++i)
        memcpy(&buf[i * lambda_bytes], &qs_test.tags[i], lambda_bytes);
    print_hex("tags", buf.data(), buf.size());
    for (size_t i = 0; i < total_bits; ++i)
        memcpy(&buf[i * lambda_bytes], &qs_test.keys[i], lambda_bytes);
    print_hex("keys", buf.data(), buf.size());
    uint8_t delta_b[lambda_bytes];
    memcpy(delta_b, &delta, lambda_bytes);
    print_hex("delta", delta_b, lambda_bytes);
    print_hex("chal2", qs_test.challenge.data(), qs_test.challenge.size());
    print_hex("pk", pk_packed.data(), VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>);
    print_hex("h", pk_packed.data() + VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>,
              VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>);
    print_hex("proof", proof, sizeof(proof));
    print_hex("check_prover", check_p, lambda_bytes);
    print_hex("check_verifier", check_v, lambda_bytes);

    // Embedding diagnostics: raw SHAKE randomness that seeds the embedding
    // table (sample_random_embedding hashes chal2[:secpar_bits/4]), and the
    // public embedding of h.
    {
        size_t in_len = secpar_to_bits(S) / 4;
        size_t out_len = VOLEMAYO_M<S> * lambda_bytes;
        std::vector<uint8_t> rnd(out_len);
        hash_state h; h.init(S);
        h.update(qs_test.challenge.data(), in_len);
        h.finalize(rnd.data(), out_len);
        print_hex("emb_randomness", rnd.data(), out_len);

        std::vector<poly_secpar<S>> table;
        sample_random_embedding<P>(table, (unsigned char*)qs_test.challenge.data());
        poly_secpar<S> hemb;
        embed_gf16_vec<P>(table, pk_packed.data() + VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>, hemb);
        uint8_t hemb_b[lambda_bytes];
        hemb.store1(hemb_b);
        print_hex("h_embedded", hemb_b, lambda_bytes);

        // First embedding-table row (16 entries) to localize table build.
        std::vector<uint8_t> row0(16 * lambda_bytes);
        for (int n = 0; n < 16; ++n)
            table[n].store1(&row0[n * lambda_bytes]);
        print_hex("table_row0", row0.data(), row0.size(), false);
    }
    printf("}");
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
