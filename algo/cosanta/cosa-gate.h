#ifndef COSA_GATE_H__
#define COSA_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

bool register_cosa_algo( algo_gate_t* gate );

void cosa_hash(void *output, const void *input, int thr_id );

#endif