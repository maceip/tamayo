// qs2_dump: reference-vector generator for the degree-2 QuickSilver used by
// the PoMFRIT One-More-MAYO proof.
//
// Compiles against the stipulated source, pq_blind_signatures
// vole/optimized_bs/quicksilver.hpp (as staged into vole/faest-cpp-tmp by
// build_opti_bs.sh), and drives quicksilver_state<S, {prover,verifier}, 2>
// directly. All randomness is a fixed-seed splitmix64, and every input the Go
// port needs (witness, VOLE tags/keys, delta, challenge) is dumped alongside
// the reference outputs (proof, prover check, verifier check) as JSON.
//
// Build (x86-64 box with the reference tree at ~/pq_blind_signatures):
//   g++ -O2 -std=c++20 -march=native -I ~/pq_blind_signatures/vole/faest-cpp-tmp \
//       qs2_dump.cpp ~/pq_blind_signatures/vole/faest-cpp-tmp/polynomials_constants.cpp \
//       -o qs2_dump
//   ./qs2_dump > quicksilver2.json

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "quicksilver.hpp"

using namespace faest;

static uint64_t sm_state = 0x746d61796f2d7173ULL; // "tamayo-qs"

static uint64_t splitmix64()
{
    uint64_t z = (sm_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static uint8_t rand_u8() { return (uint8_t)(splitmix64() & 0xff); }

static void rand_bytes(uint8_t* p, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        p[i] = rand_u8();
}

// GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1 (the field of the
// gf8_in_gf* embedding used by combine_8_bits).
static uint8_t mul_gf256(uint8_t a, uint8_t b)
{
    uint16_t c = 0;
    for (int i = 0; i < 8; ++i)
        if ((b >> i) & 1)
            c ^= (uint16_t)a << i;
    for (int i = 15; i >= 8; --i)
        if ((c >> i) & 1)
            c ^= (uint16_t)0x11b << (i - 8);
    return (uint8_t)c;
}

// GF(16) with x^4+x+1 (VOLEMAYO_MOD, the field of the gf4_in_gf* embedding
// used by combine_4_bits).
static uint8_t mul_gf16(uint8_t a, uint8_t b)
{
    uint16_t c = 0;
    for (int i = 0; i < 4; ++i)
        if ((b >> i) & 1)
            c ^= (uint16_t)a << i;
    for (int i = 7; i >= 4; --i)
        if ((c >> i) & 1)
            c ^= (uint16_t)0x13 << (i - 4);
    return (uint8_t)(c & 0xf);
}

static void set_nibble(std::vector<uint8_t>& v, size_t idx, uint8_t x)
{
    v[idx / 2] |= (x & 0xf) << ((idx % 2) * 4);
}

static void print_hex(const char* name, const uint8_t* p, size_t n, bool comma = true)
{
    printf("\"%s\":\"", name);
    for (size_t i = 0; i < n; ++i)
        printf("%02x", p[i]);
    printf("\"%s", comma ? "," : "");
}

static bool first_case = true;

template <secpar S> void run_case(const char* kind)
{
    constexpr size_t max_deg = 2;
    constexpr size_t lambda = secpar_to_bits(S);
    constexpr size_t lambda_bytes = secpar_to_bytes(S);
    const size_t n = 8;

    using QSP = quicksilver_state<S, false, max_deg>;
    using QSV = quicksilver_state<S, true, max_deg>;

    std::vector<uint8_t> witness;
    if (!strcmp(kind, "gf256_mul"))
    {
        witness.resize(3 * n);
        for (size_t i = 0; i < n; ++i)
        {
            uint8_t x = rand_u8(), y = rand_u8();
            witness[i] = x;
            witness[n + i] = y;
            witness[2 * n + i] = mul_gf256(x, y);
        }
    }
    else if (!strcmp(kind, "gf16_mul"))
    {
        witness.assign(3 * n / 2, 0);
        for (size_t i = 0; i < n; ++i)
        {
            uint8_t x = rand_u8() & 0xf, y = rand_u8() & 0xf;
            set_nibble(witness, i, x);
            set_nibble(witness, n + i, y);
            set_nibble(witness, 2 * n + i, mul_gf16(x, y));
        }
    }
    else if (!strcmp(kind, "xor_deg1"))
    {
        witness.resize(3 * n);
        for (size_t i = 0; i < n; ++i)
        {
            uint8_t x = rand_u8(), y = rand_u8();
            witness[i] = x;
            witness[n + i] = y;
            witness[2 * n + i] = x ^ y;
        }
    }
    else if (!strcmp(kind, "inv_one"))
    {
        // x and x^-1 in GF(2^8); constraint x * x^-1 + 1 == 0.
        witness.resize(2 * n);
        for (size_t i = 0; i < n; ++i)
        {
            uint8_t x = rand_u8();
            if (x == 0)
                x = 1;
            uint8_t inv = x; // x^254 by square-and-multiply over the fixed chain
            for (int k = 0; k < 6; ++k)
                inv = mul_gf256(mul_gf256(inv, inv), x);
            inv = mul_gf256(inv, inv);
            witness[i] = x;
            witness[n + i] = inv;
        }
    }
    else // scalar_mul: public GF(2^8) constant c; constraint c*x + w == 0, w = c*x
    {
        witness.resize(2 * n);
        for (size_t i = 0; i < n; ++i)
        {
            uint8_t x = rand_u8();
            witness[i] = x;
            witness[n + i] = mul_gf256((uint8_t)(0xc3 + i), x);
        }
    }

    const size_t witness_bits = 8 * witness.size();
    for (size_t i = 0; i < (max_deg - 1) * lambda_bytes; ++i)
        witness.push_back(rand_u8());

    const size_t total_bits = witness_bits + (max_deg - 1) * lambda;

    uint8_t delta_bytes[lambda_bytes];
    rand_bytes(delta_bytes, lambda_bytes);
    block_secpar<S> delta;
    memset(&delta, 0, sizeof(delta));
    memcpy(&delta, delta_bytes, lambda_bytes);

    std::vector<block_secpar<S>> keys(total_bits), tags(total_bits);
    for (size_t i = 0; i < total_bits; ++i)
    {
        uint8_t tmp[lambda_bytes];
        rand_bytes(tmp, lambda_bytes);
        memset(&keys[i], 0, sizeof(keys[i]));
        memcpy(&keys[i], tmp, lambda_bytes);
        tags[i] = keys[i];
        if ((witness[i / 8] >> (i % 8)) & 1)
            tags[i] = tags[i] ^ delta;
    }

    const size_t challenge_bytes = (3 * lambda + 64) / 8; // QS_CONSTANTS::CHALLENGE_BYTES
    std::vector<uint8_t> challenge(challenge_bytes);
    rand_bytes(challenge.data(), challenge_bytes);

    QSP prover(witness.data(), tags.data(), n, challenge.data());
    QSV verifier(keys.data(), n, delta, challenge.data());

    for (size_t i = 0; i < n; ++i)
    {
        if (!strcmp(kind, "gf256_mul"))
        {
            auto x_p = prover.load_witness_8_bits_and_combine(8 * i);
            auto y_p = prover.load_witness_8_bits_and_combine(8 * (n + i));
            auto w_p = prover.load_witness_8_bits_and_combine(8 * (2 * n + i));
            prover.add_constraint(x_p * y_p + w_p);
            auto x_v = verifier.load_witness_8_bits_and_combine(8 * i);
            auto y_v = verifier.load_witness_8_bits_and_combine(8 * (n + i));
            auto w_v = verifier.load_witness_8_bits_and_combine(8 * (2 * n + i));
            verifier.add_constraint(x_v * y_v + w_v);
        }
        else if (!strcmp(kind, "gf16_mul"))
        {
            auto x_p = prover.load_witness_4_bits_and_combine(4 * i);
            auto y_p = prover.load_witness_4_bits_and_combine(4 * (n + i));
            auto w_p = prover.load_witness_4_bits_and_combine(4 * (2 * n + i));
            prover.add_constraint(x_p * y_p + w_p);
            auto x_v = verifier.load_witness_4_bits_and_combine(4 * i);
            auto y_v = verifier.load_witness_4_bits_and_combine(4 * (n + i));
            auto w_v = verifier.load_witness_4_bits_and_combine(4 * (2 * n + i));
            verifier.add_constraint(x_v * y_v + w_v);
        }
        else if (!strcmp(kind, "xor_deg1"))
        {
            auto x_p = prover.load_witness_8_bits_and_combine(8 * i);
            auto y_p = prover.load_witness_8_bits_and_combine(8 * (n + i));
            auto w_p = prover.load_witness_8_bits_and_combine(8 * (2 * n + i));
            prover.add_constraint((x_p + y_p) + w_p);
            auto x_v = verifier.load_witness_8_bits_and_combine(8 * i);
            auto y_v = verifier.load_witness_8_bits_and_combine(8 * (n + i));
            auto w_v = verifier.load_witness_8_bits_and_combine(8 * (2 * n + i));
            verifier.add_constraint((x_v + y_v) + w_v);
        }
        else if (!strcmp(kind, "inv_one"))
        {
            auto x_p = prover.load_witness_8_bits_and_combine(8 * i);
            auto xi_p = prover.load_witness_8_bits_and_combine(8 * (n + i));
            prover.add_inverse_constraints(x_p, xi_p);
            auto x_v = verifier.load_witness_8_bits_and_combine(8 * i);
            auto xi_v = verifier.load_witness_8_bits_and_combine(8 * (n + i));
            verifier.add_inverse_constraints(x_v, xi_v);
        }
        else // scalar_mul: public constant times witness, degree-1 constraint
        {
            auto c = poly_secpar<S>::from_8_byte((uint8_t)(0xc3 + i));
            auto x_p = prover.load_witness_8_bits_and_combine(8 * i);
            auto w_p = prover.load_witness_8_bits_and_combine(8 * (n + i));
            prover.add_constraint(c * x_p + w_p);
            auto x_v = verifier.load_witness_8_bits_and_combine(8 * i);
            auto w_v = verifier.load_witness_8_bits_and_combine(8 * (n + i));
            verifier.add_constraint(c * x_v + w_v);
        }
    }

    uint8_t proof[(max_deg - 1) * lambda_bytes];
    uint8_t check_p[lambda_bytes], check_v[lambda_bytes];
    prover.prove(witness_bits, proof, check_p);
    verifier.verify(witness_bits, proof, check_v);

    if (memcmp(check_p, check_v, lambda_bytes) != 0)
    {
        fprintf(stderr, "FATAL: reference check mismatch (%s, %zu)\n", kind, lambda);
        exit(1);
    }

    if (!first_case)
        printf(",\n");
    first_case = false;
    printf("{\"secpar\":%zu,\"kind\":\"%s\",\"n\":%zu,\"witness_bits\":%zu,",
           lambda, kind, n, witness_bits);
    print_hex("witness", witness.data(), witness.size());
    std::vector<uint8_t> buf(total_bits * lambda_bytes);
    for (size_t i = 0; i < total_bits; ++i)
        memcpy(&buf[i * lambda_bytes], &tags[i], lambda_bytes);
    print_hex("tags", buf.data(), buf.size());
    for (size_t i = 0; i < total_bits; ++i)
        memcpy(&buf[i * lambda_bytes], &keys[i], lambda_bytes);
    print_hex("keys", buf.data(), buf.size());
    print_hex("delta", delta_bytes, lambda_bytes);
    print_hex("challenge", challenge.data(), challenge.size());
    print_hex("proof", proof, sizeof(proof));
    print_hex("check_prover", check_p, lambda_bytes);
    print_hex("check_verifier", check_v, lambda_bytes, false);
    printf("}");
}

int main()
{
    printf("[\n");
    for (const char* kind : {"gf256_mul", "gf16_mul", "xor_deg1", "inv_one", "scalar_mul"})
    {
        run_case<secpar::s128>(kind);
        run_case<secpar::s192>(kind);
        run_case<secpar::s256>(kind);
    }
    printf("\n]\n");
    return 0;
}
