#include "hash0x10-gate.h"

bool register_hash0x10_algo( algo_gate_t *gate )
{
#if defined (HASH0X10_8WAY)
  init_hash0x10_8way_ctx();
  gate->scanhash  = (void*)&scanhash_hash0x10_8way;
  gate->hash      = (void*)&hash0x10_8way_hash;
#elif defined (HASH0X10_4WAY)
  init_hash0x10_4way_ctx();
  gate->scanhash  = (void*)&scanhash_hash0x10_4way;
  gate->hash      = (void*)&hash0x10_4way_hash;
#else
  init_hash0x10_ctx();
  gate->scanhash  = (void*)&scanhash_hash0x10;
  gate->hash      = (void*)&hash0x10_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT ;
  return true;
};
