#include "cosa-gate.h"

bool register_cosa_algo( algo_gate_t* gate )
{
  gate->hash      = (void*)&cosa_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT | VAES256_OPT;
  return true;
};
