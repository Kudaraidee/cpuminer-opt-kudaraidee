#ifndef X11KVS_GATE_H__
#define X11KVS_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

bool register_x11kvs_algo(algo_gate_t *gate);

void x11kvs_hash(void *state, const void *input, uint8_t* cache);
int scanhash_x11kvs(struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr);
void init_x11kv_ctx();

#endif