#include "ocv2.h"

#include <string.h>
#include <inttypes.h>


int scanhash_ocv2(struct work *work, uint32_t max_nonce,unsigned long *hashes_done, struct thr_info *mythr)
{

	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	
	uint32_t _ALIGN(128) hash[8];

	uint32_t _ALIGN(128) reversed_hash[8];

	uint32_t _ALIGN(128) debug_hash[8];

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	int thr_id = mythr->id;

	int i;

	uint32_t endian_blockheader[20];
	uint32_t tmp_nonce;

	tmp_nonce = n + 1;

		for (i=0; i < 19; i++) {
			be32enc(&endian_blockheader[i], pdata[i]);
		}	

		be32enc(&endian_blockheader[19], tmp_nonce);

	//some required allocations
	char alloc1[1782];
	char alloc2[1782];
	char alloc3[4];

	ocv2_init_image((char*)endian_blockheader,alloc1,alloc2,alloc3);		
	do {
		tmp_nonce = ++n;
		be32enc(&endian_blockheader[19], tmp_nonce);
		ocv2_calculate_hash((char*)endian_blockheader,alloc1,alloc2,alloc3,(char*)hash);	

		if (swab32(hash[0]) <= Htarg) {
			pdata[19] = tmp_nonce;

		for(i=0;i<8;i++)		
			reversed_hash[i] = swab32(hash[(7-i)]);		

			if (fulltest(reversed_hash, ptarget)) {			

				*hashes_done = n - first_nonce + 1;
				return 1;
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

bool register_ocv2_algo( algo_gate_t *gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT;
  gate->scanhash              = (void*)&scanhash_ocv2;
  return true;
}