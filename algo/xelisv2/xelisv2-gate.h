#ifndef XEL2_GATE_H__
#define XEL2_GATE_H__ 1

#include "algo-gate-api.h"

bool register_xelisv2_algo( algo_gate_t* gate );
int scanhash_xelisv2( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );
void xelisv2_hash( void *state, const void *input );

#endif
