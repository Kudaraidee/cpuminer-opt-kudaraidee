#include "x11kvs-gate.h"

bool register_x11kvs_algo( algo_gate_t *gate )
{
  init_x11kv_ctx();
  gate->scanhash  = (void*)&scanhash_x11kvs;
  gate->hash      = (void*)&x11kvs_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT ;
  return true;
};