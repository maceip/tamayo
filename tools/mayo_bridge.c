// mayo_bridge: a thin C shim exposing the MAYO-C entry points the blind-loop
// dumper needs, isolating MAYO-C's macro-heavy headers from the C++ vole side.

#include <mayo.h>
#include "mayo_without_hashing.h"
#include <randombytes.h>
#include <string.h>

extern const mayo_params_t MAYO_1;
extern const mayo_params_t MAYO_3;
extern const mayo_params_t MAYO_5;

static const mayo_params_t* pick(int level)
{
    if (level == 1) return &MAYO_1;
    if (level == 3) return &MAYO_3;
    return &MAYO_5;
}

void bridge_sizes(int level, size_t* cpk, size_t* csk, size_t* epk_bytes,
                  size_t* m_bytes, size_t* sig_no_salt)
{
    const mayo_params_t* p = pick(level);
    *cpk = PARAM_cpk_bytes(p);
    *csk = PARAM_csk_bytes(p);
    *epk_bytes = (PARAM_P1_limbs(p) + PARAM_P2_limbs(p) + PARAM_P3_limbs(p)) * sizeof(uint64_t);
    *m_bytes = PARAM_m_bytes(p);
    *sig_no_salt = PARAM_sig_bytes(p) - PARAM_salt_bytes(p);
}

int bridge_keygen(int level, unsigned char* cpk, unsigned char* csk)
{
    return mayo_keypair_compact(pick(level), cpk, csk);
}

int bridge_expand_pk(int level, const unsigned char* cpk, unsigned char* epk_bytes)
{
    return mayo_expand_pk(pick(level), cpk, (uint64_t*)epk_bytes);
}

int bridge_preimage(int level, const unsigned char* csk, const unsigned char* t,
                    size_t tlen, unsigned char* bsig)
{
    size_t slen = 0;
    return mayo_sign_without_hashing(pick(level), bsig, &slen, t, tlen, csk);
}

int bridge_verify_nohash(int level, const unsigned char* cpk, const unsigned char* t,
                         size_t tlen, const unsigned char* bsig)
{
    return mayo_verify_without_hashing(pick(level), t, tlen, bsig, cpk);
}
