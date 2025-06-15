#include "evohash-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/bmw/sph_bmw.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/lyra2/lyra2.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/skein/sph_skein.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/whirlpool/sph_whirlpool.h"

#if defined(__AES__)
	#include "algo/echo/aes_ni/hash_api.h"
	#include "algo/fugue/fugue-aesni.h"
	#include "algo/groestl/aes_ni/hash-groestl.h"
#else
	#include "algo/echo/sph_echo.h"
	#include "algo/fugue/sph_fugue.h"
	#include "algo/groestl/sph_groestl.h"
#endif


void evohash(void *output, const void *input)
{
	sph_bmw512_context			ctx_bmw;	
	cubehashParam				ctx_cubehash;
	sph_hamsi512_context		ctx_hamsi;
	sph_jh512_context			ctx_jh;
	sph_keccak512_context		ctx_keccak;
	hashState_luffa				ctx_luffa;
	sph_shabal512_context		ctx_shabal;	
	sph_shavite512_context		ctx_shavite;
	simd512_context				ctx_simd;	
	sph_skein512_context		ctx_skein;
	sph_whirlpool_context		ctx_whirlpool; 

#if defined(__AES__)
	hashState_echo				ctx_echo;
	hashState_fugue				ctx_fugue;
	hashState_groestl			ctx_groestl;
#else
	sph_echo512_context			ctx_echo;
	sph_fugue512_context		ctx_fugue;
	sph_groestl512_context		ctx_groestl;
#endif	

	unsigned char hash[128] = { 0 };
	unsigned char hashA[64] = { 0 };
	unsigned char hashB[64] = { 0 };

	// CUBE512-80
	cubehashInit( &ctx_cubehash, 512, 16, 32 );
	cubehashUpdateDigest( &ctx_cubehash, (byte*)hash, (const byte*)input,80 );

	// BMW512
	sph_bmw512_init(&ctx_bmw);
	sph_bmw512(&ctx_bmw, hash, 64);
	sph_bmw512_close(&ctx_bmw, hashB);

	// LYRA2RE
	LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
	LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

	// Hamsi512
	sph_hamsi512_init(&ctx_hamsi);
	sph_hamsi512(&ctx_hamsi, hashA, 64);
	sph_hamsi512_close(&ctx_hamsi, hash);

	// Fugue512
#if defined(__AES__)
	fugue512_Init( &ctx_fugue, 512 );
	fugue512_Update( &ctx_fugue, (const void*)hash, 512 );
	fugue512_Final( &ctx_fugue, hashB );	
#else
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, (const void*) hash, 64);
	sph_fugue512_close(&ctx_fugue, hashB);	
#endif

	// LYRA2RE
	LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
	LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

	// SIMD512
	simd512_ctx( &ctx_simd, hash, hashA, 64 );
	
	// Echo512
#if defined(__AES__)
	init_echo(&ctx_echo, 512);
	update_final_echo (&ctx_echo, (BitSequence *)hashB, (const BitSequence *)hash, 512);
#else
	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, (const void*) hash, 64);
	sph_echo512_close(&ctx_echo, hashB);
#endif

	// LYRA2RE
	LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
	LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

	// CubeHash512
	cubehashInit( &ctx_cubehash, 512, 16, 32 );
	cubehashUpdateDigest( &ctx_cubehash, (byte*)hash, (const byte*)hashA, 64);

	// Shavite512
	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, hash, 64);
	sph_shavite512_close(&ctx_shavite, hashB);

	// LYRA2RE
	LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
	LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Luffa512
	luffa_full( &ctx_luffa, hashB, 512, hashA, 64 );

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // CubeHash512
	cubehashInit( &ctx_cubehash, 512, 16, 32 );
	cubehashUpdateDigest( &ctx_cubehash, (byte*)hash, (const byte*)hashA, 64);

    // Shavite512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hashB);

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Luffa512
	luffa_full( &ctx_luffa, hashB, 512, hashA, 64 );

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Hamsi512
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi, hash);

    // Fugue512
#if defined(__AES__)
	fugue512_Init( &ctx_fugue, 512 );
	fugue512_Update( &ctx_fugue, (const void*)hash, 512 );
	fugue512_Final( &ctx_fugue, hashB );	
#else
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, (const void*) hash, 64);
	sph_fugue512_close(&ctx_fugue, hashB);	
#endif

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // SIMD512
	simd512_ctx( &ctx_simd, hash, hashA, 64 );

    // Echo512
#if defined(__AES__)
	init_echo(&ctx_echo, 512);
	update_final_echo (&ctx_echo, (BitSequence *)hashB, (const BitSequence *)hash, 512);
#else
	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, (const void*) hash, 64);
	sph_echo512_close(&ctx_echo, hashB);
#endif

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // CubeHash512
	cubehashInit( &ctx_cubehash, 512, 16, 32 );
	cubehashUpdateDigest( &ctx_cubehash, (byte*)hash, (const byte*)hashA, 64);

    // Shavite512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hashB);

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Luffa512
	luffa_full( &ctx_luffa, hashB, 512, hashA, 64 );

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // CubeHash512
	cubehashInit( &ctx_cubehash, 512, 16, 32 );
	cubehashUpdateDigest( &ctx_cubehash, (byte*)hash, (const byte*)hashA, 64);

    // Shavite512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hashB);

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Luffa512
	luffa_full( &ctx_luffa, hashB, 512, hashA, 64 );

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Hamsi512
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi, hash);

    // Fugue512
#if defined(__AES__)
	fugue512_Init( &ctx_fugue, 512 );
	fugue512_Update( &ctx_fugue, (const void*)hash, 512 );
	fugue512_Final( &ctx_fugue, hashB );	
#else
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, (const void*) hash, 64);
	sph_fugue512_close(&ctx_fugue, hashB);	
#endif

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // SIMD512
    simd512_ctx( &ctx_simd, hash, hashA, 64 );

    // Echo512
#if defined(__AES__)
	init_echo(&ctx_echo, 512);
	update_final_echo (&ctx_echo, (BitSequence *)hashB, (const BitSequence *)hash, 512);
#else
	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, (const void*) hash, 64);
	sph_echo512_close(&ctx_echo, hashB);
#endif

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // CubeHash512
	cubehashInit( &ctx_cubehash, 512, 16, 32 );
	cubehashUpdateDigest( &ctx_cubehash, (byte*)hash, (const byte*)hashA, 64);

    // Shavite512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hashB);

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Luffa512
	luffa_full( &ctx_luffa, hashB, 512, hashA, 64 );

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // CubeHash512
	cubehashInit( &ctx_cubehash, 512, 16, 32 );
	cubehashUpdateDigest( &ctx_cubehash, (byte*)hash, (const byte*)hashA, 64);

    // Shavite512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hashB);

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Luffa512
	luffa_full( &ctx_luffa, hashB, 512, hashA, 64 );

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Hamsi512
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi, hash);

    // Fugue512
#if defined(__AES__)
	fugue512_Init( &ctx_fugue, 512 );
	fugue512_Update( &ctx_fugue, (const void*)hash, 512 );
	fugue512_Final( &ctx_fugue, hashB );	
#else
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, (const void*) hash, 64);
	sph_fugue512_close(&ctx_fugue, hashB);	
#endif

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // SIMD512
    simd512_ctx( &ctx_simd, hash, hashA, 64 );

    // Echo512
#if defined(__AES__)
	init_echo(&ctx_echo, 512);
	update_final_echo (&ctx_echo, (BitSequence *)hashB, (const BitSequence *)hash, 512);
#else
	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, (const void*) hash, 64);
	sph_echo512_close(&ctx_echo, hashB);
#endif

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // CubeHash512
	cubehashInit( &ctx_cubehash, 512, 16, 32 );
	cubehashUpdateDigest( &ctx_cubehash, (byte*)hash, (const byte*)hashA, 64);

    // Shavite512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hashB);

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Luffa512
	luffa_full( &ctx_luffa, hashB, 512, hashA, 64 );

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // CubeHash512
	cubehashInit( &ctx_cubehash, 512, 16, 32 );
	cubehashUpdateDigest( &ctx_cubehash, (byte*)hash, (const byte*)hashA, 64);

    // Shavite512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hashB);

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Luffa512
	luffa_full( &ctx_luffa, hashB, 512, hashA, 64 );

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Whirlpool
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashA, 64);
    sph_whirlpool_close(&ctx_whirlpool, hash);

    // Shabal512
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hash, 64);
    sph_shabal512_close(&ctx_shabal, hashB);

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // JH512
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashA, 64);
    sph_jh512_close(&ctx_jh, hash);

    // Keccak512
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash, 64);
    sph_keccak512_close(&ctx_keccak, hashB);

    // LYRA2RE
    LYRA2RE(&hashA[0], 32, &hashB[0], 32, &hashB[0], 32, 1, 8, 8);
    LYRA2RE(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    // Skein512
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hash);

    // Groestl512
#if defined(__AES__)
	init_groestl( &ctx_groestl, 64 );
	update_and_final_groestl( &ctx_groestl, hash, (const void*)hash, 512 );
#else
	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, hash, 64);
	sph_groestl512_close(&ctx_groestl, hash);
#endif

    for (int i=0; i<32; i++)
        hash[i] ^= hash[i+32];

    memcpy(output, hash, 32);

}

int scanhash_evohash( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr )
{
	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[32];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t n = pdata[19];
	const uint32_t first_nonce = pdata[19];
	const uint32_t last_nonce = max_nonce;
	const int thr_id = mythr->id;

	for ( int i=0; i < 19; i++ ) 
		be32enc( &endiandata[i], pdata[i] );

	do {
		be32enc( &endiandata[19], n ); 
		evohash( hash64, endiandata );
		if ( valid_hash( hash64, ptarget ) && !opt_benchmark )
		{
			pdata[19] = n;
			submit_solution( work, hash64, mythr );
		}
		n++;
	} while ( n < last_nonce && !work_restart[thr_id].restart );
	
	*hashes_done = n - first_nonce;
	pdata[19] = n;
	return 0;
}
