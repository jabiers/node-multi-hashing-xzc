#include "lbry.h"


//#define DEBUG_ALGO

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
    sph_sha256_context  sha256;
    sph_sha512_context  sha512;
    sph_ripemd160_context   ripemd;
} lbryhash_context_holder;

/* no need to copy, because close reinit the context */


void lbry_hash(const void* input,void* output)
{
   sph_sha256_context      ctx_sha256 __attribute__ ((aligned (64)));
   sph_sha512_context      ctx_sha512 __attribute__ ((aligned (64)));
   sph_ripemd160_context   ctx_ripemd __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) hashA[16];
   uint32_t _ALIGN(64) hashB[16];
   uint32_t _ALIGN(64) hashC[16];

   sph_sha256_init( &ctx_sha256 );
   sph_sha256 ( &ctx_sha256, input, 112 );
   sph_sha256_close( &ctx_sha256, hashA );

   sph_sha256_init( &ctx_sha256 );
   sph_sha256 ( &ctx_sha256, hashA, 32 );
   sph_sha256_close( &ctx_sha256, hashA );

   sph_sha512_init( &ctx_sha512 );
   sph_sha512 ( &ctx_sha512, hashA, 32 );
   sph_sha512_close( &ctx_sha512, hashA );  

   sph_ripemd160_init( &ctx_ripemd );
   sph_ripemd160 ( &ctx_ripemd, hashA, 32 );
   sph_ripemd160_close( &ctx_ripemd, hashB );

   sph_ripemd160_init( &ctx_ripemd );
   sph_ripemd160 ( &ctx_ripemd, hashA+8, 32 );
   sph_ripemd160_close( &ctx_ripemd, hashC );

   sph_sha256_init( &ctx_sha256 );
   sph_sha256 ( &ctx_sha256, hashB, 20 );
   sph_sha256 ( &ctx_sha256, hashC, 20 );
   sph_sha256_close( &ctx_sha256, hashA );

   sph_sha256_init( &ctx_sha256 );
   sph_sha256 ( &ctx_sha256, hashA, 32 );
   sph_sha256_close( &ctx_sha256, hashA );

   memcpy( output, hashA, 32 );

}
