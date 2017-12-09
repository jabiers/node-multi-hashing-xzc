#include "lbry.h"


//#define DEBUG_ALGO

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
    sph_sha256_context  sha256;
    sph_sha512_context  sha512;
    sph_ripemd160_context   ripemd;
} lbryhash_context_holder;

/* no need to copy, because close reinit the context */
static THREADLOCAL lbryhash_context_holder ctx;

void lbry_hash(const void* input,void* output)
{
    uint32_t hashA[16], hashB[16], hashC[16];

    memset(hashA, 0, 16 * sizeof(uint32_t));
    memset(hashB, 0, 16 * sizeof(uint32_t));
    memset(hashC, 0, 16 * sizeof(uint32_t));

    sph_sha256 (&ctx.sha256, input, 112);
    sph_sha256_close(&ctx.sha256, hashA);

    sph_sha256 (&ctx.sha256, hashA, 32);
    sph_sha256_close(&ctx.sha256, hashA);

    sph_sha512 (&ctx.sha512, hashA, 32);
    sph_sha512_close(&ctx.sha512, hashA);

    sph_ripemd160 (&ctx.ripemd, hashA, 32);
    sph_ripemd160_close(&ctx.ripemd, hashB);

    sph_ripemd160 (&ctx.ripemd, hashA+8, 32);
    sph_ripemd160_close(&ctx.ripemd, hashC);

    sph_sha256 (&ctx.sha256, hashB, 20);
    sph_sha256 (&ctx.sha256, hashC, 20);
    sph_sha256_close(&ctx.sha256, hashA);

    sph_sha256 (&ctx.sha256, hashA, 32);
    sph_sha256_close(&ctx.sha256, hashA);

    memcpy(output, hashA, 32);
}
