#include "cosa-gate.h"

bool register_cosa_algo( algo_gate_t* gate )
{
#if defined (COSA_8WAY)
  gate->scanhash  = (void*)&scanhash_8way_64in_32out;
  gate->hash      = (void*)&cosa_8way_hash;
#elif defined (COSA_4WAY)
  gate->scanhash  = (void*)&scanhash_4way_64in_32out;
  gate->hash      = (void*)&cosa_4way_hash;
#else
  gate->hash      = (void*)&cosa_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT | VAES256_OPT;
  return true;
};
