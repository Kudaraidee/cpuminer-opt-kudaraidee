#ifndef RIN_H
#define RIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "algo-gate-api.h"

bool register_rin_algo(algo_gate_t* gate);
void rinhash(void* output, const void* input);
int scanhash_rin(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);

// If compiled with OpenCL support, user may enable USE_OPENCL to use GPU path.
#ifdef USE_OPENCL
// Provide initialization/teardown declarations if needed by other modules
int init_rinhash_gpu_wrapper(const char *kernel_path);
void release_rinhash_gpu_wrapper(void);
#endif

#ifdef __cplusplus
}
#endif

#endif // RIN_H
