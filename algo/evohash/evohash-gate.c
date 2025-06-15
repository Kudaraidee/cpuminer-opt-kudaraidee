#include "evohash-gate.h"

bool register_evohash_algo( algo_gate_t* gate )
{
	gate->scanhash  = (void*)&scanhash_evohash;
	gate->hash      = (void*)&evohash;
	gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
	opt_target_factor = 256.0;
	return true;
};

