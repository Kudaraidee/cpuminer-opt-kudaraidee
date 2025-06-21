#include "cpuminer-config.h"
#include "x11kvs-gate.h"

#if !defined(X11_8WAY) && !defined(X11_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/sha/sha256d.h"

#if defined(__AES__)
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#else
#include "algo/groestl/sph_groestl.h"
#include "algo/echo/sph_echo.h"
#endif

typedef struct
{
	sph_blake512_context blake;
	sph_bmw512_context bmw;
#if defined(__AES__)
	hashState_echo echo;
	hashState_groestl groestl;
#else
	sph_groestl512_context groestl;
	sph_echo512_context echo;
#endif
	sph_jh512_context jh;
	sph_keccak512_context keccak;
	sph_skein512_context skein;
	hashState_luffa luffa;
	cubehashParam cube;
	sph_shavite512_context shavite;
	simd512_context simd;
} x11kv_ctx_holder;

x11kv_ctx_holder x11kv_ctx;

void init_x11kv_ctx()
{
	sph_blake512_init(&x11kv_ctx.blake);
	sph_bmw512_init(&x11kv_ctx.bmw);
#if defined(__AES__)
	init_groestl(&x11kv_ctx.groestl, 64);
	init_echo(&x11kv_ctx.echo, 512);
#else
	sph_groestl512_init(&x11kv_ctx.groestl);
	sph_echo512_init(&x11kv_ctx.echo);
#endif
	sph_skein512_init(&x11kv_ctx.skein);
	sph_jh512_init(&x11kv_ctx.jh);
	sph_keccak512_init(&x11kv_ctx.keccak);
	cubehashInit(&x11kv_ctx.cube, 512, 16, 32);
	sph_shavite512_init(&x11kv_ctx.shavite);
}

const unsigned int HASHX11KV_MIN_NUMBER_ITERATIONS = 2;
const unsigned int HASHX11KV_MAX_NUMBER_ITERATIONS = 6;
const unsigned int HASHX11KV_NUMBER_ALGOS = 11;

void x11kv(void *state, const void *input)
{
	unsigned char hash[64] __attribute__((aligned(64)));
	unsigned char *p;
	x11kv_ctx_holder ctx;
	memcpy(&ctx, &x11kv_ctx, sizeof(x11kv_ctx));

	sph_blake512(&ctx.blake, input, 80);
	sph_blake512_close(&ctx.blake, hash);

	p = (unsigned char *)hash;
	unsigned int n = HASHX11KV_MIN_NUMBER_ITERATIONS + (p[63] % (HASHX11KV_MAX_NUMBER_ITERATIONS - HASHX11KV_MIN_NUMBER_ITERATIONS + 1));

	for (int i = 1; i < n; i++)
	{
		p = (unsigned char *)hash;
		switch (p[i] % 11)
		{
		case 0:
			sph_blake512_init(&ctx.blake);
			sph_blake512(&ctx.blake, (const void *)hash, 64);
			sph_blake512_close(&ctx.blake, hash);
			break;
		case 1:
			sph_bmw512_init(&ctx.bmw);
			sph_bmw512(&ctx.bmw, (const void *)hash, 64);
			sph_bmw512_close(&ctx.bmw, hash);
			break;
		case 2:
#if defined(__AES__)
			init_groestl(&ctx.groestl, 64);
			update_and_final_groestl(&ctx.groestl, (char *)hash,
									 (const char *)hash, 512);
#else
			sph_groestl512_init(&ctx.groestl);
			sph_groestl512(&ctx.groestl, hash, 64);
			sph_groestl512_close(&ctx.groestl, hash);
#endif
			break;
		case 3:
			sph_skein512_init(&ctx.skein);
			sph_skein512(&ctx.skein, (const void *)hash, 64);
			sph_skein512_close(&ctx.skein, hash);
			break;
		case 4:
			sph_jh512_init(&ctx.jh);
			sph_jh512(&ctx.jh, (const void *)hash, 64);
			sph_jh512_close(&ctx.jh, hash);
			break;
		case 5:
			sph_keccak512_init(&ctx.keccak);
			sph_keccak512(&ctx.keccak, (const void *)hash, 64);
			sph_keccak512_close(&ctx.keccak, hash);
			break;
		case 6:
			luffa_full( &ctx.luffa, hash, 512, hash, 64 );
			break;
		case 7:
			cubehashInit(&ctx.cube, 512, 16, 32);
			cubehashUpdate(&ctx.cube, hash, 64);
			cubehashDigest(&ctx.cube, hash);
			break;
		case 8:
			sph_shavite512_init(&ctx.shavite);
			sph_shavite512(&ctx.shavite, hash, 64);
			sph_shavite512_close(&ctx.shavite, hash);
			break;
		case 9:
			simd512_ctx( &ctx.simd, hash, hash, 64 );
			break;
		case 10:
#if defined(__AES__)
			init_echo(&ctx.echo, 512);
			update_final_echo(&ctx.echo, (BitSequence *)hash,
							  (const BitSequence *)hash, 512);
#else
			sph_echo512_init(&ctx.echo);
			sph_echo512(&ctx.echo, hash, 64);
			sph_echo512_close(&ctx.echo, hash);
#endif
			break;
		}
	}

	memcpy(state, hash, 32);
}

const uint32_t HASHX11KVS_MAX_LEVEL = 7;
const uint32_t HASHX11KVS_MIN_LEVEL = 1;
const uint32_t HASHX11KVS_MAX_DRIFT = 0xFFFF;
const uint32_t HASHX11KVS_CACHE_CHUNK = 33;
const uint32_t HASHX11KVS_CACHE_POSITIONS = 0xFFFF;
const uint32_t HASHX11KVS_CACHE_POSITIONS_2 = 0xFFFF * 2;
const uint32_t HASHX11KVS_CACHE_POSITIONS_3 = 0xFFFF * 3;
const uint32_t HASHX11KVS_CACHE_POSITIONS_4 = 0xFFFF * 4;
const uint32_t HASHX11KVS_CACHE_POSITIONS_5 = 0xFFFF * 5;
const uint32_t HASHX11KVS_CACHE_POSITIONS_6 = 0xFFFF * 6;
const uint32_t HASHX11KVS_CACHE_SIZE = 0xFFFF * 33;
const uint32_t HASHX11KVS_CACHE_SIZE_2 = 0xFFFF * 33 + 0xFFFF * 33 * 2;
const uint32_t HASHX11KVS_CACHE_SIZE_3 = 0xFFFF * 33 + 0xFFFF * 33 * 2 + 0xFFFF * 33 * 3;
const uint32_t HASHX11KVS_CACHE_SIZE_4 = 0xFFFF * 33 + 0xFFFF * 33 * 2 + 0xFFFF * 33 * 3 + 0xFFFF * 33 * 4;
const uint32_t HASHX11KVS_CACHE_SIZE_5 = 0xFFFF * 33 + 0xFFFF * 33 * 2 + 0xFFFF * 33 * 3 + 0xFFFF * 33 * 4 + 0xFFFF * 33 * 5;
const uint32_t HASHX11KVS_CACHE_SIZE_6 = 0xFFFF * 33 + 0xFFFF * 33 * 2 + 0xFFFF * 33 * 3 + 0xFFFF * 33 * 4 + 0xFFFF * 33 * 5 + 0xFFFF * 33 * 6;

void x11kvshash(void *output, const void *input, uint32_t level, uint32_t nonce, uint8_t *cache)
{
	if (cache)
	{
		if (level == HASHX11KVS_MAX_LEVEL - 1 && cache[(nonce % HASHX11KVS_CACHE_POSITIONS) * HASHX11KVS_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + ((nonce % HASHX11KVS_CACHE_POSITIONS) * HASHX11KVS_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHX11KVS_MAX_LEVEL - 2 && cache[HASHX11KVS_CACHE_SIZE + (nonce % HASHX11KVS_CACHE_POSITIONS_2) * HASHX11KVS_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHX11KVS_CACHE_SIZE + ((nonce % HASHX11KVS_CACHE_POSITIONS_2) * HASHX11KVS_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHX11KVS_MAX_LEVEL - 3 && cache[HASHX11KVS_CACHE_SIZE_2 + (nonce % HASHX11KVS_CACHE_POSITIONS_3) * HASHX11KVS_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHX11KVS_CACHE_SIZE_2 + ((nonce % HASHX11KVS_CACHE_POSITIONS_3) * HASHX11KVS_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHX11KVS_MAX_LEVEL - 4 && cache[HASHX11KVS_CACHE_SIZE_3 + (nonce % HASHX11KVS_CACHE_POSITIONS_4) * HASHX11KVS_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHX11KVS_CACHE_SIZE_3 + ((nonce % HASHX11KVS_CACHE_POSITIONS_4) * HASHX11KVS_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHX11KVS_MAX_LEVEL - 5 && cache[HASHX11KVS_CACHE_SIZE_4 + (nonce % HASHX11KVS_CACHE_POSITIONS_5) * HASHX11KVS_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHX11KVS_CACHE_SIZE_4 + ((nonce % HASHX11KVS_CACHE_POSITIONS_5) * HASHX11KVS_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHX11KVS_MAX_LEVEL - 6 && cache[HASHX11KVS_CACHE_SIZE_5 + (nonce % HASHX11KVS_CACHE_POSITIONS_6) * HASHX11KVS_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHX11KVS_CACHE_SIZE_5 + ((nonce % HASHX11KVS_CACHE_POSITIONS_6) * HASHX11KVS_CACHE_CHUNK) + 1, 32);
			return;
		}
	}

	uint8_t hash[96];
	x11kv(hash, input);

	if (level == HASHX11KVS_MIN_LEVEL)
	{
		memcpy(output, hash, 32);
		if (cache)
		{
			cache[HASHX11KVS_CACHE_SIZE_5 + (nonce % HASHX11KVS_CACHE_POSITIONS_6) * HASHX11KVS_CACHE_CHUNK] = 0xFF;
			memcpy(cache + HASHX11KVS_CACHE_SIZE_5 + ((nonce % HASHX11KVS_CACHE_POSITIONS_6) * HASHX11KVS_CACHE_CHUNK) + 1, output, 32);
		}
		return;
	}

	if (cache && level == HASHX11KVS_MAX_LEVEL)
	{
		// cache clean
		cache[((nonce - 1) % HASHX11KVS_CACHE_POSITIONS) * HASHX11KVS_CACHE_CHUNK] = 0x00;
		cache[HASHX11KVS_CACHE_SIZE + ((nonce - 1) % HASHX11KVS_CACHE_POSITIONS_2) * HASHX11KVS_CACHE_CHUNK] = 0x00;
		cache[HASHX11KVS_CACHE_SIZE_2 + ((nonce - 1) % HASHX11KVS_CACHE_POSITIONS_3) * HASHX11KVS_CACHE_CHUNK] = 0x00;
		cache[HASHX11KVS_CACHE_SIZE_3 + ((nonce - 1) % HASHX11KVS_CACHE_POSITIONS_4) * HASHX11KVS_CACHE_CHUNK] = 0x00;
		cache[HASHX11KVS_CACHE_SIZE_4 + ((nonce - 1) % HASHX11KVS_CACHE_POSITIONS_5) * HASHX11KVS_CACHE_CHUNK] = 0x00;
		cache[HASHX11KVS_CACHE_SIZE_5 + ((nonce - 1) % HASHX11KVS_CACHE_POSITIONS_6) * HASHX11KVS_CACHE_CHUNK] = 0x00;
	}

	uint8_t nextheader1[80];
	uint8_t nextheader2[80];

	uint32_t nextnonce1 = nonce + (le32dec(hash + 24) % HASHX11KVS_MAX_DRIFT);
	uint32_t nextnonce2 = nonce + (le32dec(hash + 28) % HASHX11KVS_MAX_DRIFT);

	memcpy(nextheader1, input, 76);
	le32enc(nextheader1 + 76, nextnonce1);

	memcpy(nextheader2, input, 76);
	le32enc(nextheader2 + 76, nextnonce2);

	x11kvshash(hash + 32, nextheader1, level - 1, nextnonce1, cache);
	x11kvshash(hash + 64, nextheader2, level - 1, nextnonce2, cache);

	sha256d(output, hash, 96);

	// cache store
	if (cache && level == HASHX11KVS_MAX_LEVEL - 1)
	{
		cache[(nonce % HASHX11KVS_CACHE_POSITIONS) * HASHX11KVS_CACHE_CHUNK] = 0xFF;
		memcpy(cache + ((nonce % HASHX11KVS_CACHE_POSITIONS) * HASHX11KVS_CACHE_CHUNK) + 1, output, 32);
		return;
	}

	if (cache && level == HASHX11KVS_MAX_LEVEL - 2)
	{
		cache[HASHX11KVS_CACHE_SIZE + (nonce % HASHX11KVS_CACHE_POSITIONS_2) * HASHX11KVS_CACHE_CHUNK] = 0xFF;
		memcpy(cache + HASHX11KVS_CACHE_SIZE + ((nonce % HASHX11KVS_CACHE_POSITIONS_2) * HASHX11KVS_CACHE_CHUNK) + 1, output, 32);
		return;
	}

	if (cache && level == HASHX11KVS_MAX_LEVEL - 3)
	{
		cache[HASHX11KVS_CACHE_SIZE_2 + (nonce % HASHX11KVS_CACHE_POSITIONS_3) * HASHX11KVS_CACHE_CHUNK] = 0xFF;
		memcpy(cache + HASHX11KVS_CACHE_SIZE_2 + ((nonce % HASHX11KVS_CACHE_POSITIONS_3) * HASHX11KVS_CACHE_CHUNK) + 1, output, 32);
		return;
	}

	if (cache && level == HASHX11KVS_MAX_LEVEL - 4)
	{
		cache[HASHX11KVS_CACHE_SIZE_3 + (nonce % HASHX11KVS_CACHE_POSITIONS_4) * HASHX11KVS_CACHE_CHUNK] = 0xFF;
		memcpy(cache + HASHX11KVS_CACHE_SIZE_3 + ((nonce % HASHX11KVS_CACHE_POSITIONS_4) * HASHX11KVS_CACHE_CHUNK) + 1, output, 32);
		return;
	}

	if (cache && level == HASHX11KVS_MAX_LEVEL - 5)
	{
		cache[HASHX11KVS_CACHE_SIZE_4 + (nonce % HASHX11KVS_CACHE_POSITIONS_5) * HASHX11KVS_CACHE_CHUNK] = 0xFF;
		memcpy(cache + HASHX11KVS_CACHE_SIZE_4 + ((nonce % HASHX11KVS_CACHE_POSITIONS_5) * HASHX11KVS_CACHE_CHUNK) + 1, output, 32);
		return;
	}
}

void x11kvs_hash(void *state, const void *input, uint8_t *cache)
{
	x11kvshash(state, input, HASHX11KVS_MAX_LEVEL, le32dec(((uint8_t *)input) + 76), cache);
}

int scanhash_x11kvs(struct work *work, uint32_t max_nonce,
					uint64_t *hashes_done, struct thr_info *mythr)
{
	uint32_t endiandata[20] __attribute__((aligned(64)));
	uint32_t hash64[8] __attribute__((aligned(64)));
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	int thr_id = mythr->id;
	const uint32_t Htarg = ptarget[7];
	uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0x10000000};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0};

	uint8_t *cache = (uint8_t*) malloc(HASHX11KVS_CACHE_SIZE_6);

	memset(cache, 0x00, HASHX11KVS_CACHE_SIZE_6);

	// big endian encode 0..18 uint32_t, 64 bits at a time
	swab32_array(endiandata, pdata, 20);

	for (int m = 0; m < 6; m++)
	{
		if (Htarg <= htmax[m])
		{
			uint32_t mask = masks[m];
			do
			{
				pdata[19] = ++n;
				le32enc(&endiandata[19], n);
				x11kvs_hash(hash64, &endiandata, cache);

				if ((hash64[7] & mask) == 0)
				{
					if (fulltest(hash64, ptarget))
					{
						submit_solution(work, hash64, mythr);
					}
				}
			} while (n < max_nonce && !work_restart[thr_id].restart);
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	free(cache);
	return 0;
}
#endif
