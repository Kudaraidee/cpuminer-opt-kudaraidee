#ifndef HASH0X10_GATE_H__
#define HASH0X10_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define HASH0X10_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define HASH0X10_4WAY 1
#endif

bool register_hash0x10_algo( algo_gate_t* gate );
#if defined(HASH0X10_8WAY)

void hash0x10_8way_hash( void *state, const void *input );
int scanhash_hash0x10_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_hash0x10_8way_ctx();

#elif defined(HASH0X10_4WAY)

void hash0x10_4way_hash( void *state, const void *input );
int scanhash_hash0x10_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_hash0x10_4way_ctx();

#else

void hash0x10_hash( void *state, const void *input );
int scanhash_hash0x10( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_hash0x10_ctx();

#endif

#endif
