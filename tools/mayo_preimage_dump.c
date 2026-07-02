// mayo_preimage_dump: reference vectors for the MAYO preimage sampler
// (mayo_sign_without_hashing) that backs One-More-MAYO's blind sign_2.
// Links MAYO-C only. For each of MAYO_1/3/5: keygen a compact keypair, pick a
// random target t (m_bytes), compute bsig = mayo_sign_without_hashing(csk, t),
// assert mayo_verify_without_hashing(cpk, t, bsig), and dump csk/cpk/t/bsig.

#include <mayo.h>
#include "mayo_without_hashing.h"
#include <randombytes.h>
#include <stdio.h>
#include <string.h>

extern const mayo_params_t MAYO_1;
extern const mayo_params_t MAYO_3;
extern const mayo_params_t MAYO_5;

static int first = 1;
static void ph(const char* n, const unsigned char* p, size_t k, int comma)
{
    printf("\"%s\":\"", n);
    for (size_t i = 0; i < k; i++) printf("%02x", p[i]);
    printf("\"%s", comma ? "," : "");
}

static void run(const mayo_params_t* p, const char* name)
{
    int m_bytes = PARAM_m_bytes(p);
    int csk = PARAM_csk_bytes(p);
    int cpk = PARAM_cpk_bytes(p);
    int sig_no_salt = PARAM_sig_bytes(p) - PARAM_salt_bytes(p);

    unsigned char* pk = malloc(cpk);
    unsigned char* sk = malloc(csk);
    unsigned char* t = malloc(m_bytes);
    unsigned char* bsig = malloc(sig_no_salt + 64);

    if (mayo_keypair_compact(p, pk, sk) != MAYO_OK) { fprintf(stderr, "keygen fail %s\n", name); exit(1); }
    randombytes(t, m_bytes);

    size_t slen = 0;
    if (mayo_sign_without_hashing(p, bsig, &slen, t, m_bytes, sk) != MAYO_OK) {
        fprintf(stderr, "preimage fail %s\n", name); exit(1);
    }
    if (slen != (size_t)sig_no_salt) { fprintf(stderr, "slen %zu != %d\n", slen, sig_no_salt); exit(1); }
    if (mayo_verify_without_hashing(p, t, m_bytes, bsig, pk) != MAYO_OK) {
        fprintf(stderr, "verify_without_hashing fail %s\n", name); exit(1);
    }

    if (!first) printf(",\n");
    first = 0;
    printf("{\"name\":\"%s\",\"m\":%d,\"n\":%d,\"o\":%d,\"k\":%d,\"m_bytes\":%d,\"sig_bytes\":%d,",
           name, PARAM_m(p), PARAM_n(p), PARAM_o(p), PARAM_k(p), m_bytes, sig_no_salt);
    ph("csk", sk, csk, 1);
    ph("cpk", pk, cpk, 1);
    ph("t", t, m_bytes, 1);
    ph("bsig", bsig, sig_no_salt, 0);
    printf("}");

    free(pk); free(sk); free(t); free(bsig);
}

int main(void)
{
    printf("[\n");
    run(&MAYO_1, "mayo_1");
    run(&MAYO_3, "mayo_3");
    run(&MAYO_5, "mayo_5");
    printf("\n]\n");
    return 0;
}
