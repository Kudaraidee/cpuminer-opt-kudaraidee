#include "rinhash-gate.h"
#include "miner.h"
#include "algo-gate-api.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <malloc.h>  // _aligned_malloc, _aligned_free
#include "algo/blake3/blake3.h"
#include "algo/blake3/blake3_impl.h"
#include "sha3/SimpleFIPS202.h"
#include "algo/argon2d/argon2d/argon2.h"  // Update path to argon2d header

typedef struct {
    blake3_hasher blake;
    argon2_context argon;
} rin_context_holder;


#ifdef _WIN32
    #include <malloc.h>
    #define aligned_malloc _aligned_malloc
    #define aligned_free   _aligned_free
#else
void* aligned_malloc(size_t size, size_t alignment) {
    void* ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) return NULL;
    return ptr;
}

void aligned_free(void* ptr) {
    free(ptr);
}
#endif

__thread rin_context_holder* rin_ctx;

// RinHash implementation
void rinhash(void* state, const void* input)
{
    if (rin_ctx == NULL) {
        rin_ctx = (rin_context_holder*) aligned_malloc(sizeof(rin_context_holder), 64);
        if (!rin_ctx) {
            fprintf(stderr, "Failed to allocate rin_ctx\n");
            memset(state, 0, 32);
            return;
        }
    }
    uint8_t blake3_out[32];
    blake3_hasher_init(&rin_ctx->blake);
    blake3_hasher_update(&rin_ctx->blake, input, 80); // Block header size
    blake3_hasher_finalize(&rin_ctx->blake, blake3_out, 32);

    // Argon2d parameters
    const char* salt_str = "RinCoinSalt";
    uint8_t argon2_out[32];
    argon2_context context = {0};
    context.out = argon2_out;
    context.outlen = 32;
    context.pwd = blake3_out;
    context.pwdlen = 32;
    context.salt = (uint8_t*)salt_str;
    context.saltlen = strlen(salt_str);
    context.t_cost = 2;
    context.m_cost = 64;
    context.lanes = 1;
    context.threads = 1;
    context.version = ARGON2_VERSION_13;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;

    if (argon2d_ctx(&context) != ARGON2_OK) {
        fprintf(stderr, "Argon2d failed!\n");
        memset(state, 0, 32);
        return;
    }
    
    // SHA3-256
    uint8_t sha3_out[32];
    SHA3_256(sha3_out, (const uint8_t *)argon2_out, 32);
    
    memcpy(state, sha3_out, 32);
}

int scanhash_rinhash(struct work *work, uint32_t max_nonce,
    uint64_t *hashes_done, struct thr_info *mythr)
{
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    int thr_id = mythr->id;
    uint8_t hash[32];

    do {
        n++;
        pdata[19] = n;

        rinhash(hash, pdata);
        uint32_t hash32[8];

        for (int i = 0; i < 8; i++) {
            hash32[i] = ((uint32_t)hash[i*4 + 0]) |
                        ((uint32_t)hash[i*4 + 1] << 8) |
                        ((uint32_t)hash[i*4 + 2] << 16) |
                        ((uint32_t)hash[i*4 + 3] << 24);
}
        if (fulltest(hash32, ptarget)) {
            submit_solution(work, hash, mythr);
            break;
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    pdata[19] = n;
    *hashes_done = n - first_nonce + 1;
    return 0;
}

void rin_build_block_header( struct work* g_work, uint32_t version,
       uint32_t *prevhash, uint32_t *merkle_tree, uint32_t ntime,
       uint32_t nbits, unsigned char *final_sapling_hash )
{
   int i;

   memset( g_work->data, 0, sizeof(g_work->data) );
   g_work->data[0] = version;
   g_work->sapling = opt_sapling;

   if (have_stratum) {
      g_work->data[0] = bswap_32(version);
      for (int i = 0; i < 8; i++)
         g_work->data[1 + i] = bswap_32(prevhash[i]);
   }
   else for (int i = 0; i < 8; i++)
      g_work->data[1 + i] = bswap_32(prevhash[7 - i]);
   memcpy(&g_work->data[9], merkle_tree, 32);

   g_work->data[ algo_gate.ntime_index ] = ntime;
   g_work->data[ algo_gate.nbits_index ] = nbits;
   g_work->data[ algo_gate.nonce_index ] = 0;

   if ( g_work->sapling )
   {
      if ( have_stratum )
         for ( i = 0; i < 8; i++ )
            g_work->data[20 + i] = le32dec( (uint32_t*)final_sapling_hash + i );
      else
      {
         for ( i = 0; i < 8; i++ )
            g_work->data[27 - i] = le32dec( (uint32_t*)final_sapling_hash + i );
         g_work->data[19] = 0;
      }      
      g_work->data[28] = 0x80000000;
      g_work->data[29] = 0x00000000;
      g_work->data[30] = 0x00000000;
      g_work->data[31] = 0x00000380;
   }
   else
   {
      g_work->data[20] = 0x80000000;
      g_work->data[31] = 0x00000280;
   }
}

void rin_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   uchar merkle_tree[64] = { 0 };

   algo_gate.gen_merkle_root( merkle_tree, sctx );
   algo_gate.build_block_header( g_work, le32dec(sctx->job.version),
          (uint32_t*) sctx->job.prevhash, (uint32_t*) merkle_tree,
          bswap_32(le32dec(sctx->job.ntime)), bswap_32(le32dec(sctx->job.nbits)),
          sctx->job.final_sapling_hash );
}

// Register algorithm
bool register_rin_algo( algo_gate_t* gate )
{
    gate->scanhash = (void*)&scanhash_rinhash;
    gate->hash = (void*)&rinhash;
    gate->optimizations = SSE2_OPT | AVX_OPT | AVX2_OPT | AVX512_OPT;
    gate->build_stratum_request = (void*)&std_be_build_stratum_request;
    gate->build_block_header = (void*)&rin_build_block_header;
    gate->build_extraheader = (void*)&rin_build_extraheader;
    return true;
}
