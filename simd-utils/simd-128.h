#if !defined(SIMD_128_H__)
#define SIMD_128_H__ 1

#if defined(__SSE2__)

///////////////////////////////////////////////////////////////////////////
//
//                 128 bit SSE vectors
//
// SSE2 is required for 128 bit integer support. Some functions are also
// optimized with SSSE3, SSE4.1 or AVX. Some of these more optimized
// functions don't have SSE2 equivalents and their use would break SSE2
// compatibility.
//
// Constants are an issue with simd. Simply put, immediate constants don't
// exist. All simd constants either reside in memory or a register and
// must be loaded from memory or generated at run time.
//
// Due to the cost of generating constants it is more efficient to
// define a local const for repeated references to the same constant.
//
// One common use for simd constants is as a control index for vector
// instructions like blend and shuffle. Alhough the ultimate instruction
// may execute in a single clock cycle, generating the control index adds
// several more cycles to the entire operation. 
//
// All of the utilities here assume all data is in registers except
// in rare cases where arguments are pointers.
//
// Intrinsics automatically promote from REX to VEX when AVX is available
// but ASM needs to be done manually.
//
///////////////////////////////////////////////////////////////////////////


// Efficient and convenient moving bwtween GP & low bits of XMM.
// Use VEX when available to give access to xmm8-15 and zero extend for
// larger vectors.

static inline __m128i mm128_mov64_128( const uint64_t n )
{
  __m128i a;
#if defined(__AVX__)
  asm( "vmovq %1, %0\n\t" : "=x"(a) : "r"(n) );
#else
  asm( "movq %1, %0\n\t" : "=x"(a) : "r"(n) );
#endif
  return  a;
}

static inline __m128i mm128_mov32_128( const uint32_t n )
{
  __m128i a;
#if defined(__AVX__)
  asm( "vmovd %1, %0\n\t" : "=x"(a) : "r"(n) );
#else  
  asm( "movd %1, %0\n\t" : "=x"(a) : "r"(n) );
#endif
  return  a;
}

static inline uint64_t mm128_mov128_64( const __m128i a )
{
  uint64_t n;
#if defined(__AVX__)
  asm( "vmovq %1, %0\n\t" : "=r"(n) : "x"(a) );
#else  
  asm( "movq %1, %0\n\t" : "=r"(n) : "x"(a) );
#endif
  return  n;
}

static inline uint32_t mm128_mov128_32( const __m128i a )
{
  uint32_t n;
#if defined(__AVX__)
  asm( "vmovd %1, %0\n\t" : "=r"(n) : "x"(a) );
#else  
  asm( "movd %1, %0\n\t" : "=r"(n) : "x"(a) );
#endif
  return  n;
}

// Pseudo constants

#define m128_zero      _mm_setzero_si128()
#define m128_one_128   mm128_mov64_128( 1 )
#define m128_one_64    _mm_shuffle_epi32( mm128_mov64_128( 1 ), 0x44 )
#define m128_one_32    _mm_shuffle_epi32( mm128_mov32_128( 1 ), 0x00 )
#define m128_one_16    _mm_shuffle_epi32( \
                                 mm128_mov32_128( 0x00010001 ), 0x00 )
#define m128_one_8     _mm_shuffle_epi32( \
                                 mm128_mov32_128( 0x01010101 ), 0x00 )

// ASM avoids the need to initialize return variable to avoid compiler warning.
// Macro abstracts function parentheses to look like an identifier.

static inline __m128i mm128_neg1_fn()
{
   __m128i a;
#if defined(__AVX__) 
   asm( "vpcmpeqq %0, %0, %0\n\t" : "=x"(a) );
#else
   asm( "pcmpeqq %0, %0\n\t" : "=x"(a) );
#endif
   return a;
}
#define m128_neg1    mm128_neg1_fn()


// const functions work best when arguments are immediate constants or
// are known to be in registers. If data needs to loaded from memory or cache
// use set.

// Equivalent of set1, broadcast 64 bit integer to all elements.
#define m128_const1_64( i ) _mm_shuffle_epi32( mm128_mov64_128( i ), 0x44 )
#define m128_const1_32( i ) _mm_shuffle_epi32( mm128_mov32_128( i ), 0x00 )

#if defined(__SSE4_1__)

// Assign 64 bit integers to respective elements: {hi, lo}
#define m128_const_64( hi, lo ) \
   _mm_insert_epi64( mm128_mov64_128( lo ), hi, 1 )

#else  // No insert in SSE2

#define m128_const_64  _mm_set_epi64x

#endif


//
// Basic operations without equivalent SIMD intrinsic

// Bitwise not (~v)  
#define mm128_not( v )          _mm_xor_si128( (v), m128_neg1 ) 

// Unary negation of elements (-v)
#define mm128_negate_64( v )    _mm_sub_epi64( m128_zero, v )
#define mm128_negate_32( v )    _mm_sub_epi32( m128_zero, v )  
#define mm128_negate_16( v )    _mm_sub_epi16( m128_zero, v )  

// Clear (zero) 32 bit elements based on bits set in 4 bit mask.
// Fast, avoids using vector mask, but only available for 128 bit vectors.
#define mm128_mask_32( a, mask ) \
   _mm_castps_si128( _mm_insert_ps( _mm_castsi128_ps( a ), \
                                    _mm_castsi128_ps( a ), mask ) )

// Add 4 values, fewer dependencies than sequential addition.
#define mm128_add4_64( a, b, c, d ) \
   _mm_add_epi64( _mm_add_epi64( a, b ), _mm_add_epi64( c, d ) )

#define mm128_add4_32( a, b, c, d ) \
   _mm_add_epi32( _mm_add_epi32( a, b ), _mm_add_epi32( c, d ) )

#define mm128_add4_16( a, b, c, d ) \
   _mm_add_epi16( _mm_add_epi16( a, b ), _mm_add_epi16( c, d ) )

#define mm128_add4_8( a, b, c, d ) \
   _mm_add_epi8( _mm_add_epi8( a, b ), _mm_add_epi8( c, d ) )

#define mm128_xor4( a, b, c, d ) \
   _mm_xor_si128( _mm_xor_si128( a, b ), _mm_xor_si128( c, d ) )

// Horizontal vector testing

#if defined(__SSE4_1__)

#define mm128_allbits0( a )    _mm_testz_si128(   a, a )
#define mm128_allbits1( a )    _mm_testc_si128(   a, m128_neg1 )
// probably broken, avx2 is
//#define mm128_allbitsne( a )   _mm_testnzc_si128( a, m128_neg1 )
#define mm128_anybits0( a )    mm128_allbits1( a )
#define mm128_anybits1( a )    mm128_allbits0( a )

#else   // SSE2

// Bit-wise test of entire vector, useful to test results of cmp.
#define mm128_anybits0( a ) (uint128_t)(a)
#define mm128_anybits1( a ) (((uint128_t)(a))+1)

#define mm128_allbits0( a ) ( !mm128_anybits1(a) )
#define mm128_allbits1( a ) ( !mm128_anybits0(a) )

#endif // SSE4.1 else SSE2

//
// Vector pointer cast

// p = any aligned pointer
// returns p as pointer to vector type
#define castp_m128i(p) ((__m128i*)(p))

// p = any aligned pointer
// returns *p, watch your pointer arithmetic
#define cast_m128i(p) (*((__m128i*)(p)))

// p = any aligned pointer, i = scaled array index
// returns value p[i]
#define casti_m128i(p,i) (((__m128i*)(p))[(i)])

// p = any aligned pointer, o = scaled offset
// returns pointer p+o
#define casto_m128i(p,o) (((__m128i*)(p))+(o))


// Memory functions
// Mostly for convenience, avoids calculating bytes.
// Assumes data is alinged and integral.
// n = number of __m128i, bytes/16

// Memory functions
// Mostly for convenience, avoids calculating bytes.
// Assumes data is alinged and integral.
// n = number of __m128i, bytes/16

static inline void memset_zero_128( __m128i *dst,  const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m128_zero; }

static inline void memset_128( __m128i *dst, const __m128i a, const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_128( __m128i *dst, const __m128i *src, const int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }


//
// Bit rotations

// AVX512VL has implemented bit rotation for 128 bit vectors with
// 64 and 32 bit elements.

// compiler doesn't like when a variable is used for the last arg of
// _mm_rol_epi32, must be "8 bit immediate". Oddly _mm_slli has the same
// specification but works with a variable. Therefore use rol_var where
// necessary.
// sm3-hash-4way.c has one instance where mm128_rol_var_32 is required.

#define mm128_ror_var_64( v, c ) \
   _mm_or_si128( _mm_srli_epi64( v, c ), _mm_slli_epi64( v, 64-(c) ) )

#define mm128_rol_var_64( v, c ) \
   _mm_or_si128( _mm_slli_epi64( v, c ), _mm_srli_epi64( v, 64-(c) ) )

#define mm128_ror_var_32( v, c ) \
   _mm_or_si128( _mm_srli_epi32( v, c ), _mm_slli_epi32( v, 32-(c) ) )

#define mm128_rol_var_32( v, c ) \
   _mm_or_si128( _mm_slli_epi32( v, c ), _mm_srli_epi32( v, 32-(c) ) )


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define mm128_ror_64    _mm_ror_epi64
#define mm128_rol_64    _mm_rol_epi64
#define mm128_ror_32    _mm_ror_epi32
#define mm128_rol_32    _mm_rol_epi32

#else

#define mm128_ror_64   mm128_ror_var_64
#define mm128_rol_64   mm128_rol_var_64
#define mm128_ror_32   mm128_ror_var_32
#define mm128_rol_32   mm128_rol_var_32

#endif   // AVX512 else

#define mm128_ror_16( v, c ) \
   _mm_or_si128( _mm_srli_epi16( v, c ), _mm_slli_epi16( v, 16-(c) ) )

#define mm128_rol_16( v, c ) \
   _mm_or_si128( _mm_slli_epi16( v, c ), _mm_srli_epi16( v, 16-(c) ) )

//
// Rotate vector elements accross all lanes

#define mm128_swap_64( v )    _mm_shuffle_epi32( v, 0x4e )
#define mm128_ror_1x32( v )   _mm_shuffle_epi32( v, 0x39 )
#define mm128_rol_1x32( v )   _mm_shuffle_epi32( v, 0x93 )
//#define mm128_swap_64( v )    _mm_alignr_epi8( v, v,  8 )
//#define mm128_ror_1x32( v )   _mm_alignr_epi8( v, v,  4 )
//#define mm128_rol_1x32( v )   _mm_alignr_epi8( v, v, 12 )
#define mm128_ror_1x16( v )   _mm_alignr_epi8( v, v,  2 )
#define mm128_rol_1x16( v )   _mm_alignr_epi8( v, v, 14 )
#define mm128_ror_1x8( v )    _mm_alignr_epi8( v, v,  1 )
#define mm128_rol_1x8( v )    _mm_alignr_epi8( v, v, 15 )

// Rotate by c bytes
#define mm128_ror_x8( v, c )  _mm_alignr_epi8( v, c )
#define mm128_rol_x8( v, c )  _mm_alignr_epi8( v, 16-(c) )


// Invert vector: {3,2,1,0} -> {0,1,2,3}
#define mm128_invert_32( v ) _mm_shuffle_epi32( v, 0x1b )

#if defined(__SSSE3__)

#define mm128_invert_16( v ) \
   _mm_shuffle_epi8( v, mm128_const_64( 0x0100030205040706, \
                                        0x09080b0a0d0c0f0e )
#define mm128_invert_8( v ) \
   _mm_shuffle_epi8( v, mm128_const_64( 0x0001020304050607, \
                                        0x08090a0b0c0d0e0f )

#endif   // SSSE3


//
// Rotate elements within lanes.

#define mm128_swap64_32( v )  _mm_shuffle_epi32( v, 0xb1 )

#define mm128_rol64_8( v, c ) \
     _mm_or_si128( _mm_slli_epi64( v, ( ( (c)<<3 ) ), \
                   _mm_srli_epi64( v, ( ( 64 - ( (c)<<3 ) ) ) )

#define mm128_ror64_8( v, c ) \
     _mm_or_si128( _mm_srli_epi64( v, ( ( (c)<<3 ) ), \
                   _mm_slli_epi64( v, ( ( 64 - ( (c)<<3 ) ) ) )

#define mm128_rol32_8( v, c ) \
     _mm_or_si128( _mm_slli_epi32( v, ( ( (c)<<3 ) ), \
                   _mm_srli_epi32( v, ( ( 32 - ( (c)<<3 ) ) ) )

#define mm128_ror32_8( v, c ) \
     _mm_or_si128( _mm_srli_epi32( v, ( ( (c)<<3 ) ), \
                   _mm_slli_epi32( v, ( ( 32 - ( (c)<<3 ) ) ) )
           

//
// Endian byte swap.

#if defined(__SSSE3__)

#define mm128_bswap_64( v ) \
   _mm_shuffle_epi8( v, m128_const_64( 0x08090a0b0c0d0e0f, \
                                       0x0001020304050607 ) )

#define mm128_bswap_32( v ) \
   _mm_shuffle_epi8( v, m128_const_64( 0x0c0d0e0f08090a0b, \
                                       0x0405060700010203 ) )

#define mm128_bswap_16( v ) \
   _mm_shuffle_epi8( v, m128_const_64( 0x0e0f0c0d0a0b0809, \
                                       0x0607040502030001 )

// 8 byte qword * 8 qwords * 2 lanes = 128 bytes
#define mm128_block_bswap_64( d, s ) do \
{ \
   __m128i ctl = m128_const_64(  0x08090a0b0c0d0e0f, 0x0001020304050607 ); \
  casti_m128i( d, 0 ) = _mm_shuffle_epi8( casti_m128i( s, 0 ), ctl ); \
  casti_m128i( d, 1 ) = _mm_shuffle_epi8( casti_m128i( s, 1 ), ctl ); \
  casti_m128i( d, 2 ) = _mm_shuffle_epi8( casti_m128i( s, 2 ), ctl ); \
  casti_m128i( d, 3 ) = _mm_shuffle_epi8( casti_m128i( s, 3 ), ctl ); \
  casti_m128i( d, 4 ) = _mm_shuffle_epi8( casti_m128i( s, 4 ), ctl ); \
  casti_m128i( d, 5 ) = _mm_shuffle_epi8( casti_m128i( s, 5 ), ctl ); \
  casti_m128i( d, 6 ) = _mm_shuffle_epi8( casti_m128i( s, 6 ), ctl ); \
  casti_m128i( d, 7 ) = _mm_shuffle_epi8( casti_m128i( s, 7 ), ctl ); \
} while(0)

// 4 byte dword * 8 dwords * 4 lanes = 128 bytes
#define mm128_block_bswap_32( d, s ) do \
{ \
   __m128i ctl = m128_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
  casti_m128i( d, 0 ) = _mm_shuffle_epi8( casti_m128i( s, 0 ), ctl ); \
  casti_m128i( d, 1 ) = _mm_shuffle_epi8( casti_m128i( s, 1 ), ctl ); \
  casti_m128i( d, 2 ) = _mm_shuffle_epi8( casti_m128i( s, 2 ), ctl ); \
  casti_m128i( d, 3 ) = _mm_shuffle_epi8( casti_m128i( s, 3 ), ctl ); \
  casti_m128i( d, 4 ) = _mm_shuffle_epi8( casti_m128i( s, 4 ), ctl ); \
  casti_m128i( d, 5 ) = _mm_shuffle_epi8( casti_m128i( s, 5 ), ctl ); \
  casti_m128i( d, 6 ) = _mm_shuffle_epi8( casti_m128i( s, 6 ), ctl ); \
  casti_m128i( d, 7 ) = _mm_shuffle_epi8( casti_m128i( s, 7 ), ctl ); \
} while(0)

#else  // SSE2

// Use inline function instead of macro due to multiple statements.
static inline __m128i mm128_bswap_64( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
}

static inline __m128i mm128_bswap_32( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
}

static inline __m128i mm128_bswap_16( __m128i v )
{
  return _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
}

static inline void mm128_block_bswap_64( __m128i *d, const __m128i *s )
{
   d[0] = mm128_bswap_64( s[0] );
   d[1] = mm128_bswap_64( s[1] );
   d[2] = mm128_bswap_64( s[2] );
   d[3] = mm128_bswap_64( s[3] );
   d[4] = mm128_bswap_64( s[4] );
   d[5] = mm128_bswap_64( s[5] );
   d[6] = mm128_bswap_64( s[6] );
   d[7] = mm128_bswap_64( s[7] );
}

static inline void mm128_block_bswap_32( __m128i *d, const __m128i *s )
{
   d[0] = mm128_bswap_32( s[0] );
   d[1] = mm128_bswap_32( s[1] );
   d[2] = mm128_bswap_32( s[2] );
   d[3] = mm128_bswap_32( s[3] );
   d[4] = mm128_bswap_32( s[4] );
   d[5] = mm128_bswap_32( s[5] );
   d[6] = mm128_bswap_32( s[6] );
   d[7] = mm128_bswap_32( s[7] );
}

#endif // SSSE3 else SSE2

//
// Rotate in place concatenated 128 bit vectors as one 256 bit vector.

// Swap 128 bit vectorse.

#define mm128_swap256_128( v1, v2 ) \
   v1 = _mm_xor_si128( v1, v2 ); \
   v2 = _mm_xor_si128( v1, v2 ); \
   v1 = _mm_xor_si128( v1, v2 );


// Concatenate v1 & v2 and rotate as one 256 bit vector.
#if defined(__SSE4_1__)

#define mm128_ror256_64( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 8 ); \
           v1 = _mm_alignr_epi8( v2, v1, 8 ); \
           v2 = t; \
} while(0)

#define mm128_rol256_64( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 8 ); \
           v2 = _mm_alignr_epi8( v2, v1, 8 ); \
           v1 = t; \
} while(0)

#define mm128_ror256_32( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 4 ); \
           v1 = _mm_alignr_epi8( v2, v1, 4 ); \
           v2 = t; \
} while(0)

#define mm128_rol256_32( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 12 ); \
           v2 = _mm_alignr_epi8( v2, v1, 12 ); \
           v1 = t; \
} while(0)

#define mm128_ror256_16( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 2 ); \
           v1 = _mm_alignr_epi8( v2, v1, 2 ); \
           v2 = t; \
} while(0)

#define mm128_rol256_16( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 14 ); \
           v2 = _mm_alignr_epi8( v2, v1, 14 ); \
           v1 = t; \
} while(0)

#define mm128_ror256_8( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 1 ); \
           v1 = _mm_alignr_epi8( v2, v1, 1 ); \
           v2 = t; \
} while(0)

#define mm128_rol256_8( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 15 ); \
           v2 = _mm_alignr_epi8( v2, v1, 15 ); \
           v1 = t; \
} while(0)

#else  // SSE2

#define mm128_ror256_64( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_srli_si128( v1, 8 ), \
                              _mm_slli_si128( v2, 8 ) ); \
           v2 = _mm_or_si128( _mm_srli_si128( v2, 8 ), \
                              _mm_slli_si128( v1, 8 ) ); \
           v1 = t; \
} while(0)

#define mm128_rol256_64( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_slli_si128( v1, 8 ), \
                              _mm_srli_si128( v2, 8 ) ); \
           v2 = _mm_or_si128( _mm_slli_si128( v2, 8 ), \
                              _mm_srli_si128( v1, 8 ) ); \
           v1 = t; \
} while(0)

#define mm128_ror256_32( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_srli_si128( v1, 4 ), \
                              _mm_slli_si128( v2, 12 ) ); \
           v2 = _mm_or_si128( _mm_srli_si128( v2, 4 ), \
                              _mm_slli_si128( v1, 12 ) ); \
           v1 = t; \
} while(0)

#define mm128_rol256_32( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_slli_si128( v1, 4 ), \
                              _mm_srli_si128( v2, 12 ) ); \
           v2 = _mm_or_si128( _mm_slli_si128( v2, 4 ), \
                              _mm_srli_si128( v1, 12 ) ); \
           v1 = t; \
} while(0)

#define mm128_ror256_16( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_srli_si128( v1, 2 ), \
                              _mm_slli_si128( v2, 14 ) ); \
           v2 = _mm_or_si128( _mm_srli_si128( v2, 2 ), \
                              _mm_slli_si128( v1, 14 ) ); \
           v1 = t; \
} while(0)

#define mm128_rol256_16( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_slli_si128( v1, 2 ), \
                              _mm_srli_si128( v2, 14 ) ); \
           v2 = _mm_or_si128( _mm_slli_si128( v2, 2 ), \
                              _mm_srli_si128( v1, 14 ) ); \
           v1 = t; \
} while(0)

#define mm128_ror256_8( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_srli_si128( v1, 1 ), \
                              _mm_slli_si128( v2, 15 ) ); \
           v2 = _mm_or_si128( _mm_srli_si128( v2, 1 ), \
                              _mm_slli_si128( v1, 15 ) ); \
           v1 = t; \
} while(0)

#define mm128_rol256_8( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_slli_si128( v1, 1 ), \
                              _mm_srli_si128( v2, 15 ) ); \
           v2 = _mm_or_si128( _mm_slli_si128( v2, 1 ), \
                              _mm_srli_si128( v1, 15 ) ); \
           v1 = t; \
} while(0)

#endif  // SSE4.1 else SSE2

#endif // __SSE2__
#endif // SIMD_128_H__
