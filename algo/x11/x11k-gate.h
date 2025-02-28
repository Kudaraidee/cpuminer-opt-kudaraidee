#ifndef X11K_GATE_H__
#define X11K_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

const uint64_t X11KGetUint64(const void *data, int pos);

bool register_x11k_algo(algo_gate_t *gate);

void x11k_hash(void *state, const void *input);
int scanhash_x11k(struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr);
void init_x11k_ctx();

#endif
