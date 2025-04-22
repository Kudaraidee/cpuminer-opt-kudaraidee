#ifndef XEL2_H
#define XEL2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "algo-gate-api.h"

bool register_xelisv2_algo(algo_gate_t* gate);
void xelisv2_hash(void* output, const void* input);
int scanhash_xelisv2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);

#ifdef __cplusplus
}
#endif

#endif