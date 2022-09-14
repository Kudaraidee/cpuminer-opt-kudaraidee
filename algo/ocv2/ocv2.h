#ifndef OCV2_H__
#define OCV2_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

int scanhash_ocv2(struct work *work, uint32_t max_nonce,unsigned long *hashes_done, struct thr_info *mythr);

#endif

