#include "cosa-gate.h"

#if !defined(COSA_8WAY) && !defined(COSA_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
#endif 
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sph_sha2.h"
#include "algo/haval/sph-haval.h"
#include "algo/gost/sph_gost.h"
#include "algo/lyra2/lyra2.h"

__thread uint64_t* lyra2z_matrix;

bool lyra2z_thread_init()
{
//   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 8; // nCols
//   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;
//   int i = (int64_t)ROW_LEN_BYTES * 8; // nRows;
   const int i = BLOCK_LEN_INT64 * 8 * 8 * 8;
   lyra2z_matrix = _mm_malloc( i, 64 );
   return lyra2z_matrix;
}

union _cosa_context_overlay
{
	sph_blake512_context     blake;
	sph_bmw512_context       bmw;
#if defined(__AES__)
    hashState_groestl        groestl;
    hashState_echo           echo;
#else
    sph_groestl512_context   groestl;
    sph_echo512_context      echo;
#endif
	sph_jh512_context        jh;
	sph_keccak512_context    keccak;
	sph_skein512_context     skein;
	sph_luffa512_context     luffa;
	sph_cubehash512_context  cubehash;
	sph_shavite512_context   shavite;
	sph_simd512_context      simd;
	sph_hamsi512_context     hamsi;
	sph_fugue512_context     fugue;
	sph_shabal512_context    shabal;
	sph_whirlpool_context    whirlpool;
	sph_sha512_context       sha512;
	sph_haval256_5_context   haval;
	sph_gost512_context      gost;
};
typedef union _cosa_context_overlay cosa_context_overlay;

void cosa_hash( void *output, const void *input, int thr_id )
{
	unsigned char _ALIGN(128) hash[128],hashB[128],hashC[128],hashD[128];
	
	cosa_context_overlay ctx;
	int size = 64;
	
	sph_blake512_init(&ctx.blake);
	sph_blake512(&ctx.blake, input, 80);
	sph_blake512_close(&ctx.blake, hash);

	sph_bmw512_init(&ctx.bmw);
	sph_bmw512(&ctx.bmw, hash, size);
	sph_bmw512_close(&ctx.bmw, hash);

	#if defined(__AES__)
		init_groestl( &ctx.groestl, size );
		update_and_final_groestl( &ctx.groestl, (char*)hash, (const char*)hash, size<<3 );
	#else
		sph_groestl512_init(&ctx.groestl);
		sph_groestl512(&ctx.groestl, hash, size);
		sph_groestl512_close(&ctx.groestl, hash);
	#endif

	sph_skein512_init(&ctx.skein);
	sph_skein512(&ctx.skein, hash, size);
	sph_skein512_close(&ctx.skein, hash);

	sph_jh512_init(&ctx.jh);
	sph_jh512(&ctx.jh, hash, size);
	sph_jh512_close(&ctx.jh, hash);

	sph_keccak512_init(&ctx.keccak);
	sph_keccak512(&ctx.keccak, hash, size);
	sph_keccak512_close(&ctx.keccak, hash);

	sph_luffa512_init(&ctx.luffa);
	sph_luffa512(&ctx.luffa, hash, size);
	sph_luffa512_close(&ctx.luffa, hash);

	sph_cubehash512_init(&ctx.cubehash);
	sph_cubehash512(&ctx.cubehash, hash, size);
	sph_cubehash512_close(&ctx.cubehash, hash);

	sph_shavite512_init(&ctx.shavite);
	sph_shavite512(&ctx.shavite, hash, size);
	sph_shavite512_close(&ctx.shavite, hash);

	sph_simd512_init(&ctx.simd);
	sph_simd512(&ctx.simd, hash, size);
	sph_simd512_close(&ctx.simd, hash);

	#if defined(__AES__)
		init_echo( &ctx.echo, size );
        update_final_echo ( &ctx.echo, (BitSequence *)hash,(const BitSequence *)hash, size<<3 );
	#else
	    sph_echo512_init(&ctx.echo);
	    sph_echo512(&ctx.echo, hash, size);
	    sph_echo512_close(&ctx.echo, hash);
	#endif
	
	sph_hamsi512_init(&ctx.hamsi);
	sph_hamsi512(&ctx.hamsi, hash, size);
	sph_hamsi512_close(&ctx.hamsi, hash);

	sph_fugue512_init(&ctx.fugue);
	sph_fugue512(&ctx.fugue, hash, size);
	sph_fugue512_close(&ctx.fugue, hash);

	sph_shabal512_init(&ctx.shabal);
	sph_shabal512(&ctx.shabal, hash, size);
	sph_shabal512_close(&ctx.shabal, hash);

	sph_whirlpool_init(&ctx.whirlpool);
	sph_whirlpool(&ctx.whirlpool, hash, size);
	sph_whirlpool_close(&ctx.whirlpool, hash);

	sph_sha512_init(&ctx.sha512);
	sph_sha512(&ctx.sha512,(const void*) hash, size);
	sph_sha512_close(&ctx.sha512,(void*) hash);

	memset (hashB,0x0,128);
	memset (hashC,0x0,128);
	memset (hashD,0x0,128); 

	sph_haval256_5_init(&ctx.haval);
	sph_haval256_5(&ctx.haval,(const void*) hash, size);
	sph_haval256_5_close(&ctx.haval, hashB);

	sph_gost512_init(&ctx.gost);
	sph_gost512(&ctx.gost, (const void*) hashB, size);
	sph_gost512_close(&ctx.gost, (void*) hashC);

	LYRA2Z(lyra2z_matrix, hashD, 32, hashC, 80, hashC, 80, 2, 66, 66);

	memcpy(output, hashD, 32);
	
	return 1;
}

#endif