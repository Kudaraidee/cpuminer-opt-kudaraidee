#ifndef EVO_GATE_H__
#define EVO_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

bool register_evohash_algo( algo_gate_t* gate );

void evohash( void *state, const void *input );
int scanhash_evohash( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );

#endif
