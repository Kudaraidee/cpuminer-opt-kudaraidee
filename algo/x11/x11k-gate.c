#include "x11k-gate.h"

bool register_x11k_algo( algo_gate_t *gate )
{
  init_x11k_ctx();
  gate->scanhash  = (void*)&scanhash_x11k;
  gate->hash      = (void*)&x11k_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT ;
  return true;
};
