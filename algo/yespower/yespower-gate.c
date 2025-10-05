/*-
 * Copyright 2018 Cryply team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Cryply team as part of the Cryply
 * coin.
 */
#include "yespower.h"
#include "algo-gate-api.h"

yespower_params_t yespower_params;

__thread sha256_context sha256_prehash_ctx;

bool has_eqp_roots = false;

int eqp_get_work_data_size() { return 101 + STD_WORK_DATA_SIZE; }

void eqp_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   uchar merkle_tree[64] = { 0 };
   size_t t;

   algo_gate.gen_merkle_root( merkle_tree, sctx );
   algo_gate.build_block_header( g_work, le32dec( sctx->job.version ),
                  (uint32_t*) sctx->job.prevhash, (uint32_t*) merkle_tree,
                  le32dec( sctx->job.ntime ), le32dec(sctx->job.nbits), NULL);
   for ( t = 0; t < 16; t++ )
      g_work->data[ 20+t ] = le32dec( (uint32_t*)sctx->job.extra + t);
}

#if defined(__SSE2__) || defined(__aarch64__)

int yespower_hash( const char *input, char *output, int thrid )
{
   return yespower_tls( input, has_eqp_roots ? 181 : 80, &yespower_params,
           (yespower_binary_t*)output, thrid );
}

#else

int yespower_hash_ref( const char *input, char *output, int thrid )
{
   return yespower_tls_ref( input, has_eqp_roots ? 181 : 80, &yespower_params,
           (yespower_binary_t*)output, thrid );
}

#endif

// YESPOWER

int scanhash_yespower( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) vhash[8];
   uint32_t _ALIGN(64) endiandata[46] = { 0 };
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   bool received_eqp_roots = false;
   uint8_t eqproots[] = { 0xb8,0x42,0xea,0x73,
                          0xbe,0x5f,0xb5,0x92,
                          0xf1,0x34,0x70,0xf9,
                          0xcc,0x31,0xb9,0x26,
                          0xf5,0x0f,0x19,0x1c,
                          0x7e,0x8c,0xec,0x8f,
                          0x7e,0xe9,0xdb,0xcc,
                          0xcd,0x02,0x38,0x1c,
                          0x56,0xe8,0x1f,0x17,
                          0x1b,0xcc,0x55,0xa6,
                          0xff,0x83,0x45,0xe6,
                          0x92,0xc0,0xf8,0x6e,
                          0x5b,0x48,0xe0,0x1b,
                          0x99,0x6c,0xad,0xc0,
                          0x01,0x62,0x2f,0xb5,
                          0xe3,0x63,0xb4,0x21 };

   has_eqp_roots = opt_algo == ALGO_YESPOWEREQPAY ? true : false ;

   for ( int k = 0; k < 19; k++ )
      be32enc( &endiandata[k], pdata[k] );
   endiandata[19] = n;

   if (has_eqp_roots) {
      for ( int k = 20; k < 36; k++ ) {
         be32enc( &endiandata[k], pdata[k] );
         if (pdata[k]) received_eqp_roots = true;
      }
      if (!received_eqp_roots) {
         if (opt_debug)
            applog(LOG_INFO,"scanhash_yespower: (EQPAY) No roots received. "
                            "Falling back to using hard coded root defaults.");
         memcpy(&endiandata[20], eqproots, 64);
      }
      if (opt_debug) {
         char s[129];
         bin2hex(s, (unsigned char *)&endiandata[20], 64);
         applog(LOG_DEBUG,"scanhash_yespower: added EQPAY roots: %s", s);
      }
      // For EQPAY, the remainder is PoS related and has to be zero. Only
      // the last full size uint32_t has to be 0xffffff
      endiandata[44] = 0xffffffff;
   }

   // do sha256 prehash
   sha256_ctx_init( &sha256_prehash_ctx );
   sha256_update( &sha256_prehash_ctx, endiandata, 64 );

   do {
      if ( algo_gate.hash( (char*)endiandata, (char*)vhash, thr_id ) )
      if unlikely( valid_hash( vhash, ptarget ) && !opt_benchmark )
      {
          be32enc( pdata+19, n );
          submit_solution( work, vhash, mythr );
      }
      endiandata[19] = ++n;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

// YESPOWER-B2B

#if defined(__SSE2__) || defined(__aarch64__)

int yespower_b2b_hash( const char *input, char *output, int thrid )
{
  return yespower_b2b_tls( input, 80, &yespower_params, (yespower_binary_t*)output, thrid );
}

#else

int yespower_b2b_hash_ref( const char *input, char *output, int thrid )
{
  return yespower_b2b_tls_ref( input, 80, &yespower_params, (yespower_binary_t*)output, thrid );
}

#endif

int scanhash_yespower_b2b( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) vhash[8];
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t last_nonce = max_nonce;
   const int thr_id = mythr->id;

   for ( int k = 0; k < 19; k++ )
      be32enc( &endiandata[k], pdata[k] );
   endiandata[19] = n;

   do {
      if ( algo_gate.hash( (char*) endiandata, (char*) vhash, thr_id ) )
      if unlikely( valid_hash( vhash, ptarget ) && !opt_benchmark )
      {
          be32enc( pdata+19, n );
          submit_solution( work, vhash, mythr );
      }
      endiandata[19] = ++n;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

bool register_yespower_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;

  if ( opt_param_n )  yespower_params.N = opt_param_n;
  else                yespower_params.N = 2048;

  if ( opt_param_r )  yespower_params.r = opt_param_r;
  else                yespower_params.r = 32;

  if ( opt_param_key )
  {
     yespower_params.pers = opt_param_key;
     yespower_params.perslen = strlen( opt_param_key );
  }
  else
  {
     yespower_params.pers    = NULL;
     yespower_params.perslen = 0;
  }

  applog( LOG_NOTICE,"Yespower parameters: N= %d, R= %d", yespower_params.N,
                                                           yespower_params.r );
  if ( yespower_params.pers )
     applog( LOG_NOTICE,"Key= \"%s\"\n", yespower_params.pers );

  gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
#if (__SSE2__) || defined(__aarch64__)
  gate->hash          = (void*)&yespower_hash;
#else
  gate->hash          = (void*)&yespower_hash_ref;
#endif
  opt_target_factor = 65536.0;
  return true;
};

bool register_yespowerr16_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 4096;
  yespower_params.r       = 16;
  yespower_params.pers    = NULL;
  yespower_params.perslen = 0;
  gate->optimizations     = SSE2_OPT | SHA256_OPT | NEON_OPT;
  gate->scanhash          = (void*)&scanhash_yespower;
#if (__SSE2__) || defined(__aarch64__)
  gate->hash              = (void*)&yespower_hash;
#else
  gate->hash              = (void*)&yespower_hash_ref;
#endif
  opt_target_factor = 65536.0;
  return true;
 };

// Legacy Yescrypt (yespower v0.5)

bool register_yescrypt_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
#if (__SSE2__) || defined(__aarch64__)
   gate->hash       = (void*)&yespower_hash;
#else
   gate->hash       = (void*)&yespower_hash_ref;
#endif
   yespower_params.version = YESPOWER_0_5;
   opt_target_factor = 65536.0;

   if ( opt_param_n )  yespower_params.N = opt_param_n;
   else                yespower_params.N = 2048;

   if ( opt_param_r )  yespower_params.r = opt_param_r;
   else                yespower_params.r = 8;

   if ( opt_param_key )
   {
     yespower_params.pers = opt_param_key;
     yespower_params.perslen = strlen( opt_param_key );
   }
   else
   {
     yespower_params.pers = NULL;
     yespower_params.perslen = 0;
   }

   applog( LOG_NOTICE,"Yescrypt parameters: N= %d, R= %d.",
                                      yespower_params.N, yespower_params.r );
   if ( yespower_params.pers )
     applog( LOG_NOTICE,"Key= \"%s\"\n", yespower_params.pers );

   return true;
}


bool register_yescryptr8_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
   gate->scanhash      = (void*)&scanhash_yespower;
#if (__SSE2__) || defined(__aarch64__)
   gate->hash          = (void*)&yespower_hash;
#else
   gate->hash          = (void*)&yespower_hash_ref;
#endif
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 2048;
   yespower_params.r       = 8;
   yespower_params.pers    = "Client Key";
   yespower_params.perslen = 10;
   opt_target_factor = 65536.0;
   return true;
}

bool register_yescryptr16_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
#if (__SSE2__) || defined(__aarch64__)
   gate->hash          = (void*)&yespower_hash;
#else
   gate->hash          = (void*)&yespower_hash_ref;
#endif
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 4096;
   yespower_params.r       = 16;
   yespower_params.pers    = "Client Key";
   yespower_params.perslen = 10;
   opt_target_factor = 65536.0;
   return true;
}

bool register_yescryptr32_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
#if (__SSE2__) || defined(__aarch64__)
   gate->hash          = (void*)&yespower_hash;
#else
   gate->hash          = (void*)&yespower_hash_ref;
#endif
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 4096;
   yespower_params.r       = 32;
   yespower_params.pers    = "WaviBanana";
   yespower_params.perslen = 10;
   opt_target_factor = 65536.0;
   return true;
}

// POWER2B

bool register_power2b_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;

  yespower_params.N = 2048;
  yespower_params.r = 32;
  yespower_params.pers = "Now I am become Death, the destroyer of worlds";
  yespower_params.perslen = 46;

  applog( LOG_NOTICE,"yespower-b2b parameters: N= %d, R= %d", yespower_params.N,
                                                           yespower_params.r );
  applog( LOG_NOTICE,"Key= \"%s\"", yespower_params.pers );
  applog( LOG_NOTICE,"Key length= %d\n", yespower_params.perslen );

  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower_b2b;
#if (__SSE2__) || defined(__aarch64__)
  gate->hash          = (void*)&yespower_b2b_hash;
#else
  gate->hash          = (void*)&yespower_b2b_hash_ref;
#endif
  opt_target_factor = 65536.0;
  return true;
};

// Generic yespower + blake2b
bool register_yespower_b2b_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;

  if ( !( opt_param_n && opt_param_r ) )
  {
     applog(LOG_ERR,"Yespower-b2b N & R parameters are required");
     return false;
  }

  yespower_params.N = opt_param_n;
  yespower_params.r = opt_param_r;

  if ( opt_param_key )
  {
     yespower_params.pers = opt_param_key;
     yespower_params.perslen = strlen( opt_param_key );
  }
  else
  {
     yespower_params.pers    = NULL;
     yespower_params.perslen = 0;
  }

  applog( LOG_NOTICE,"Yespower-b2b parameters: N= %d, R= %d",
                       yespower_params.N, yespower_params.r );
  if ( yespower_params.pers )
  {
     applog( LOG_NOTICE,"Key= \"%s\"", yespower_params.pers );
     applog( LOG_NOTICE,"Key length= %d\n", yespower_params.perslen );
  }  

  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower_b2b;
#if (__SSE2__) || defined(__aarch64__)
  gate->hash          = (void*)&yespower_b2b_hash;
#else
  gate->hash          = (void*)&yespower_b2b_hash_ref;
#endif
  opt_target_factor = 65536.0;
  return true;
};

bool register_yespowersugar_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 2048;
  yespower_params.r       = 32;
  yespower_params.pers    = "Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote";
  yespower_params.perslen = 74;
  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  opt_target_factor = 65536.0;
  return true;
 };

bool register_cpupower_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 2048;
  yespower_params.r       = 32;
  yespower_params.pers    = "CPUpower: The number of CPU working or available for proof-of-work mining";
  yespower_params.perslen = 73;
  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  opt_target_factor = 65536.0;
  return true;
 };

bool register_yespowerarwn_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 2048;
  yespower_params.r       = 32;
  yespower_params.pers    = (const uint8_t *)"ARWN";
  yespower_params.perslen = 4;
  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  opt_target_factor = 65536.0;
  return true;
 };

bool register_yespowerurx_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 2048;
  yespower_params.r       = 32;
  yespower_params.pers    = (const uint8_t *)"UraniumX";
  yespower_params.perslen = 8;
  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  opt_target_factor = 65536.0;
  return true;
 };

bool register_yespowermgpc_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 2048;
  yespower_params.r       = 32;
  yespower_params.pers    = "Magpies are birds of the Corvidae family.";
  yespower_params.perslen = 41;
  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  opt_target_factor = 65536.0;
  return true;
 };

bool register_yespoweradvc_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 2048;
  yespower_params.r       = 32;
  yespower_params.pers    = "Let the quest begin";
  yespower_params.perslen = 19;
  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  opt_target_factor = 65536.0;
  return true;
 };

bool register_interchained_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 1024;
  yespower_params.r       = 8;
  yespower_params.pers    = NULL;
  yespower_params.perslen = 0;
  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  opt_target_factor = 65536.0;
  return true;
 };

bool register_yespowereqpay_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 2048;
  yespower_params.r       = 32;
  yespower_params.pers    = "The gods had gone away, and the ritual of the religion continued senselessly, uselessly.";
  yespower_params.perslen = 88;
  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
#if (__SSE2__) || defined(__aarch64__)
  gate->hash          = (void*)&yespower_hash;
#else
  gate->hash          = (void*)&yespower_hash_ref;
#endif
  gate->get_work_data_size = (void*)&eqp_get_work_data_size;
  gate->build_extraheader  = (void*)&eqp_build_extraheader;
  opt_target_factor = 65536.0;
  return true;
 };
