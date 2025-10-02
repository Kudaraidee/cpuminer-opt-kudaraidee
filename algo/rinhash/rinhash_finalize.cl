// rinhash_finalize.cl
// Finalize kernel: nén/XOR memory do Argon2 tạo ra và tính SHA3-256.
// Host phải đảm bảo memory layout và buffer_row_pitch khớp với argon2 preproc/kernel.

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable
typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;

#define ARGON2_BLOCK_SIZE 1024
#define ARGON2_QWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 8)

// --- KECCAK/SHA3-256 (compact) ---
static inline ulong ROTR64(ulong x, uint r) {
    return (x >> r) | (x << (64 - r));
}
#define KECCAK_ROUNDS 24
static const ulong keccak_rconst[24] = {
    0x0000000000000001UL,0x0000000000008082UL,0x800000000000808aUL,0x8000000080008000UL,
    0x000000000000808bUL,0x0000000080000001UL,0x8000000080008081UL,0x8000000000008009UL,
    0x000000000000008aUL,0x0000000000000088UL,0x0000000080008009UL,0x000000008000000aUL,
    0x000000008000808bUL,0x800000000000008bUL,0x8000000000008089UL,0x8000000000008003UL,
    0x8000000000008002UL,0x8000000000000080UL,0x000000000000800aUL,0x800000008000000aUL,
    0x8000000080008081UL,0x8000000000008080UL,0x0000000080000001UL,0x8000000080008008UL
};

static inline void keccakf(ulong st[25]) {
    for (int round = 0; round < KECCAK_ROUNDS; ++round) {
        ulong C[5];
        for (int x = 0; x < 5; ++x) {
            C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            ulong d = C[(x+4)%5] ^ ROTR64(C[(x+1)%5], 1);
            for (int y = 0; y < 25; y += 5) st[y + x] ^= d;
        }
        ulong B[25];
        const int r[25] = {
             0,  1, 62, 28, 27, 36, 44,  6, 55, 20, 3, 10, 43, 25, 39,
            41, 45, 15, 21,  8, 18,  2, 61, 56, 14
        };
        const int piIndex[25] = {
             0,  6, 12, 18, 24, 3,  9, 10, 16, 22, 1,  7, 13, 19, 20,
             4,  5, 11, 17, 23, 2,  8, 14, 15, 21
        };
        for (int i = 0; i < 25; ++i) B[piIndex[i]] = ROTR64(st[i], r[i]);
        for (int i = 0; i < 25; ++i) st[i] = B[i] ^ (~B[(i+5)%25] & B[(i+10)%25]);
        st[0] ^= keccak_rconst[round];
    }
}

void sha3_256_local(const uchar *in, uint inlen, uchar *out32) {
    ulong st[25];
    for (int i=0;i<25;i++) st[i]=0UL;
    const uint rate = 136;
    uint offset = 0;
    while (inlen >= rate) {
        for (uint i = 0; i < rate/8; ++i) {
            ulong lane = 0;
            for (int b = 0; b < 8; ++b) lane |= (ulong)in[offset + i*8 + b] << (8*b);
            st[i] ^= lane;
        }
        keccakf(st);
        offset += rate;
        inlen -= rate;
    }
    uchar tmp[136];
    for (uint i=0;i<rate;i++) tmp[i]=0;
    for (uint i=0;i<inlen;i++) tmp[i]=in[offset+i];
    tmp[inlen] = 0x06;
    tmp[rate-1] |= 0x80;
    for (uint i=0;i<rate/8;i++) {
        ulong lane = 0;
        for (int b=0;b<8;b++) lane |= (ulong)tmp[i*8 + b] << (8*b);
        st[i] ^= lane;
    }
    keccakf(st);
    uint out_off = 0;
    uint needed = 32;
    uint i = 0;
    while (needed > 0) {
        for (i = 0; i < (rate/8) && needed > 0; ++i) {
            ulong lane = st[i];
            for (int b = 0; b < 8 && needed > 0; ++b) {
                out32[out_off++] = (uchar)((lane >> (8*b)) & 0xFF);
                needed--;
            }
        }
        if (needed > 0) keccakf(st);
    }
}

// finalize kernel
// memory_qwords: global qwords buffer produced by Argon2 kernel (ulong qwords)
// buffer_row_qwords: qwords per job row (i.e., blocks_per_job * ARGON2_QWORDS_IN_BLOCK)
// m_cost_blocks: number of blocks (m_cost) used in Argon2 (as blocks)
__kernel void rinhash_finalize(__global const ulong *memory_qwords,
                               uint buffer_row_qwords,
                               uint m_cost_blocks,
                               uint jobs,
                               __global uchar *out_hashes) // out: jobs * 32
{
    uint job = get_global_id(0);
    if (job >= jobs) return;

    // pointer to job's region (in qwords)
    __global const uchar *job_mem_bytes = (const __global uchar*)(memory_qwords + (size_t)job * buffer_row_qwords);

    uchar final32[32];
    for (int i = 0; i < 32; ++i) final32[i] = 0;

    size_t block_bytes = ARGON2_BLOCK_SIZE;
    // XOR-compress first m_cost_blocks' first 32 bytes (must be aligned with CPU finalization)
    for (uint b = 0; b < m_cost_blocks; ++b) {
        size_t base = (size_t)b * block_bytes;
        for (int i = 0; i < 32; ++i) {
            final32[i] ^= job_mem_bytes[base + i];
        }
    }

    // SHA3-256(final32) -> out_hashes[job*32 ..]
    sha3_256_local(final32, 32, out_hashes + job*32);
}
