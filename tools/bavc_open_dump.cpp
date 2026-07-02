// bavc_open_dump: reference vectors for ggm_forest_bavc::open. Commits a forest
// from a fixed seed/iv, then opens at a chosen Delta and dumps the opening
// bytes, so the Go MayoForestOpen can be checked byte-exact.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "parameters.hpp"
#include "constants.hpp"
#include "faest_keys.hpp"
#include "vole_commit.inc"
#include "small_vole.inc"
#include "util.hpp"

using namespace faest;

static uint64_t sm = 0x6f70656e2d746d79ULL;
static uint64_t sx() { uint64_t z=(sm+=0x9e3779b97f4a7c15ULL); z=(z^(z>>30))*0xbf58476d1ce4e5b9ULL; z=(z^(z>>27))*0x94d049bb133111ebULL; return z^(z>>31);} 
static void rb(uint8_t*p,size_t n){for(size_t i=0;i<n;i++)p[i]=(uint8_t)(sx()&0xff);}

static bool first=true;
static void ph(const char* n,const uint8_t*p,size_t k,bool c=true){printf("\"%s\":\"",n);for(size_t i=0;i<k;i++)printf("%02x",p[i]);printf("\"%s",c?",":"");}

template <typename P> void run(const char* name)
{
    using CP=P::CONSTS; constexpr auto S=P::secpar_v; constexpr size_t lb=secpar_to_bytes(S);
    uint8_t seed_b[lb], iv_b[16], delta_b[lb];
    rb(seed_b,lb); rb(iv_b,16); rb(delta_b,lb);
    block_secpar<S> seed; block128 iv;
    memset(&seed,0,sizeof(seed)); memcpy(&seed,seed_b,lb);
    memset(&iv,0,sizeof(iv)); memcpy(&iv,iv_b,16);

    vole_block* u=(vole_block*)aligned_alloc(alignof(vole_block),CP::VOLE_COL_BLOCKS*sizeof(vole_block));
    vole_block* v=(vole_block*)aligned_alloc(alignof(vole_block),P::secpar_bits*CP::VOLE_COL_BLOCKS*sizeof(vole_block));
    block_secpar<S>* forest=(block_secpar<S>*)aligned_alloc(alignof(block_secpar<S>),P::bavc_t::COMMIT_NODES*sizeof(block_secpar<S>));
    unsigned char* hashed=(unsigned char*)aligned_alloc(alignof(block_2secpar<S>),P::bavc_t::COMMIT_LEAVES*P::leaf_hash_t::hash_len);
    std::vector<uint8_t> commitment(CP::VOLE_COMMIT_SIZE); uint8_t check[CP::VOLE_COMMIT_CHECK_SIZE];
    vole_commit<P>(seed,iv,forest,hashed,u,v,commitment.data(),check);

    std::array<uint8_t,P::delta_bits_v> delta_bytes;
    expand_bits_to_bytes(delta_bytes.data(),P::delta_bits_v,delta_b);

    std::vector<uint8_t> opening(P::bavc_t::OPEN_SIZE);
    P::bavc_t::open(forest,hashed,delta_bytes.data(),opening.data());

    if(!first)printf(",\n"); first=false;
    printf("{\"name\":\"%s\",\"secpar\":%zu,\"open_size\":%zu,\"delta_bits\":%zu,",name,(size_t)secpar_to_bits(S),(size_t)P::bavc_t::OPEN_SIZE,(size_t)P::delta_bits_v);
    ph("seed",seed_b,lb); ph("iv",iv_b,16); ph("delta",delta_b,lb);
    ph("delta_bytes",delta_bytes.data(),P::delta_bits_v);
    ph("opening",opening.data(),opening.size(),false);
    printf("}");
    free(u);free(v);free(forest);free(hashed);
}

int main(){printf("[\n");run<v1::mayo_128_s>("mayo_128_s");run<v1::mayo_192_s>("mayo_192_s");run<v1::mayo_256_s>("mayo_256_s");printf("\n]\n");return 0;}
