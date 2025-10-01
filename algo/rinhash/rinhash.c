// Modified rinhash.c — GPU offload for Argon2d+SHA3 via OpenCL.
// Build with -DUSE_OPENCL and link -lOpenCL to enable GPU path.
// Kernel file expected at algo/rinhash/rinhash.cl

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
#include "algo/argon2d/argon2d/argon2.h"  // CPU fallback

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

typedef struct {
    blake3_hasher blake;
    argon2_context argon;
} rin_context_holder;

__thread rin_context_holder* rin_ctx;

// ----------------- OpenCL GPU support (optional) -----------------
#ifdef USE_OPENCL
#include <CL/cl.h>

#define ARGON_BLOCK_SIZE 1024  // Argon2 block size in bytes

static cl_context cl_ctx = NULL;
static cl_command_queue cl_queue = NULL;
static cl_program cl_prog = NULL;
static cl_kernel cl_kernel_rinhash = NULL;
static int cl_initialized = 0;
static cl_device_id cl_device = NULL;

static int init_rinhash_gpu(const char *kernel_path)
{
    cl_int err;
    cl_uint num_platforms = 0;
    err = clGetPlatformIDs(0, NULL, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) return 0;

    cl_platform_id *platforms = (cl_platform_id*)malloc(sizeof(cl_platform_id)*num_platforms);
    clGetPlatformIDs(num_platforms, platforms, NULL);

    // Pick first platform and first GPU device
    cl_platform_id platform = platforms[0];
    cl_uint num_devices = 0;
    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &cl_device, &num_devices);
    if (err != CL_SUCCESS) { free(platforms); return 0; }

    cl_ctx = clCreateContext(NULL, 1, &cl_device, NULL, NULL, &err);
    if (err != CL_SUCCESS) { free(platforms); return 0; }

    cl_queue = clCreateCommandQueue(cl_ctx, cl_device, 0, &err);
    if (err != CL_SUCCESS) { clReleaseContext(cl_ctx); cl_ctx = NULL; free(platforms); return 0; }

    // Load kernel source
    FILE *f = fopen(kernel_path, "rb");
    if (!f) { clReleaseCommandQueue(cl_queue); clReleaseContext(cl_ctx); cl_queue = NULL; cl_ctx = NULL; free(platforms); return 0; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *source = (char*)malloc(fsize + 1);
    fread(source, 1, fsize, f);
    source[fsize] = '\0';
    fclose(f);

    const char *srcs[1] = { source };
    cl_prog = clCreateProgramWithSource(cl_ctx, 1, srcs, NULL, &err);
    free(source);
    if (err != CL_SUCCESS) { clReleaseCommandQueue(cl_queue); clReleaseContext(cl_ctx); cl_queue = NULL; cl_ctx = NULL; free(platforms); return 0; }

    // Build program
    err = clBuildProgram(cl_prog, 1, &cl_device, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t log_size;
        clGetProgramBuildInfo(cl_prog, cl_device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
        char *log = (char*)malloc(log_size + 1);
        clGetProgramBuildInfo(cl_prog, cl_device, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
        log[log_size] = '\0';
        fprintf(stderr, "OpenCL build error:\n%s\n", log);
        free(log);
        clReleaseProgram(cl_prog);
        clReleaseCommandQueue(cl_queue);
        clReleaseContext(cl_ctx);
        cl_prog = NULL; cl_queue = NULL; cl_ctx = NULL; free(platforms);
        return 0;
    }

    cl_kernel_rinhash = clCreateKernel(cl_prog, "rinhash_kernel", &err);
    if (err != CL_SUCCESS) {
        clReleaseProgram(cl_prog);
        clReleaseCommandQueue(cl_queue);
        clReleaseContext(cl_ctx);
        cl_prog = NULL; cl_queue = NULL; cl_ctx = NULL; free(platforms);
        return 0;
    }

    cl_initialized = 1;
    free(platforms);
    return 1;
}

static void release_rinhash_gpu()
{
    if (!cl_initialized) return;
    if (cl_kernel_rinhash) clReleaseKernel(cl_kernel_rinhash);
    if (cl_prog) clReleaseProgram(cl_prog);
    if (cl_queue) clReleaseCommandQueue(cl_queue);
    if (cl_ctx) clReleaseContext(cl_ctx);
    cl_kernel_rinhash = NULL; cl_prog = NULL; cl_queue = NULL; cl_ctx = NULL;
    cl_initialized = 0;
}
#endif // USE_OPENCL
// ----------------- end OpenCL support -----------------

// CPU rinhash (unchanged)
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

    // Argon2d parameters (CPU)
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

// GPU-accelerated scanhash
int scanhash_rinhash(struct work *work, uint32_t max_nonce,
    uint64_t *hashes_done, struct thr_info *mythr)
{
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    int thr_id = mythr->id;
    uint8_t hash[32];

#ifdef USE_OPENCL
    // initialize OpenCL once
    if (!cl_initialized) {
        if (!init_rinhash_gpu("algo/rinhash/rinhash.cl")) {
            goto cpu_path;
        }
    }

    // CONFIG: tune batch_size based on GPU memory; default conservative value
    const uint32_t batch_size = 64; // tune this: smaller -> less GPU mem, larger -> throughput
    const uint32_t argon_m_cost = 64; // must match CPU params (m_cost)
    const uint32_t argon_t_cost = 2;
    const uint32_t ARGON_BLOCK = ARGON_BLOCK_SIZE; // 1024

    while (n < max_nonce && !work_restart[thr_id].restart) {
        uint32_t remaining = max_nonce - n;
        uint32_t current_batch = (remaining > batch_size) ? batch_size : remaining;
        // Prepare header copy (80 bytes template)
        uint8_t hdr_template[80];
        memcpy(hdr_template, pdata, 80);

        // Prepare host-side array of blake3 outputs (current_batch * 32)
        size_t blake3_inputs_size = (size_t)current_batch * 32;
        uint8_t *blake3_inputs = (uint8_t*)malloc(blake3_inputs_size);
        if (!blake3_inputs) goto cpu_path;

        // For each nonce in batch compute blake3(header_with_nonce)
        for (uint32_t i = 0; i < current_batch; ++i) {
            uint32_t nonce = n + 1 + i;
            // write nonce into header copy (assumes nonce at bytes 76..79 little-endian)
            uint8_t tmp_hdr[80];
            memcpy(tmp_hdr, hdr_template, 80);
            tmp_hdr[76] = (uint8_t)(nonce & 0xFF);
            tmp_hdr[77] = (uint8_t)((nonce >> 8) & 0xFF);
            tmp_hdr[78] = (uint8_t)((nonce >> 16) & 0xFF);
            tmp_hdr[79] = (uint8_t)((nonce >> 24) & 0xFF);

            // compute blake3 for this header
            blake3_hasher h;
            blake3_hasher_init(&h);
            blake3_hasher_update(&h, tmp_hdr, 80);
            blake3_hasher_finalize(&h, blake3_inputs + (size_t)i * 32, 32);
        }

        // create OpenCL buffers
        cl_int err;
        cl_context ctx = cl_ctx;
        cl_command_queue queue = cl_queue;
        cl_kernel kernel = cl_kernel_rinhash;

        cl_mem buf_blake3 = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, blake3_inputs_size, blake3_inputs, &err);
        if (err != CL_SUCCESS) { free(blake3_inputs); goto cpu_path; }

        // allocate argon memory: current_batch * argon_m_cost * ARGON_BLOCK
        size_t argon_mem_size = (size_t)current_batch * argon_m_cost * ARGON_BLOCK;
        cl_mem buf_argon = clCreateBuffer(ctx, CL_MEM_READ_WRITE, argon_mem_size, NULL, &err);
        if (err != CL_SUCCESS) { clReleaseMemObject(buf_blake3); free(blake3_inputs); goto cpu_path; }

        size_t out_size = (size_t)current_batch * 32;
        cl_mem buf_out = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, out_size, NULL, &err);
        if (err != CL_SUCCESS) { clReleaseMemObject(buf_blake3); clReleaseMemObject(buf_argon); free(blake3_inputs); goto cpu_path; }

        // Set kernel args:
        // 0: blake3_inputs, 1: out, 2: argon_mem, 3: m_cost, 4: t_cost, 5: batch_size
        err  = clSetKernelArg(kernel, 0, sizeof(cl_mem), &buf_blake3);
        err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &buf_out);
        err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &buf_argon);
        err |= clSetKernelArg(kernel, 3, sizeof(cl_uint), &argon_m_cost);
        err |= clSetKernelArg(kernel, 4, sizeof(cl_uint), &argon_t_cost);
        err |= clSetKernelArg(kernel, 5, sizeof(cl_uint), &current_batch);
        if (err != CL_SUCCESS) { clReleaseMemObject(buf_blake3); clReleaseMemObject(buf_argon); clReleaseMemObject(buf_out); free(blake3_inputs); goto cpu_path; }

        size_t global = current_batch;
        err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global, NULL, 0, NULL, NULL);
        if (err != CL_SUCCESS) { clReleaseMemObject(buf_blake3); clReleaseMemObject(buf_argon); clReleaseMemObject(buf_out); free(blake3_inputs); goto cpu_path; }

        // Read back results
        uint8_t *results = (uint8_t*)malloc(out_size);
        err = clEnqueueReadBuffer(queue, buf_out, CL_TRUE, 0, out_size, results, 0, NULL, NULL);
        if (err != CL_SUCCESS) { free(results); clReleaseMemObject(buf_blake3); clReleaseMemObject(buf_argon); clReleaseMemObject(buf_out); free(blake3_inputs); goto cpu_path; }

        // Check each result against target
        int found = 0;
        uint32_t found_nonce = 0;
        uint8_t found_hash[32];
        for (uint32_t i = 0; i < current_batch; ++i) {
            uint8_t *hptr = results + (size_t)i * 32;
            uint32_t hash32[8];
            for (int j = 0; j < 8; j++) {
                hash32[j] = ((uint32_t)hptr[j*4 + 0]) |
                            ((uint32_t)hptr[j*4 + 1] << 8) |
                            ((uint32_t)hptr[j*4 + 2] << 16) |
                            ((uint32_t)hptr[j*4 + 3] << 24);
            }
            if (fulltest(hash32, ptarget)) {
                found = 1;
                found_nonce = n + 1 + i;
                memcpy(found_hash, hptr, 32);
                break;
            }
        }

        free(results);
        clReleaseMemObject(buf_blake3);
        clReleaseMemObject(buf_argon);
        clReleaseMemObject(buf_out);
        free(blake3_inputs);

        if (found) {
            pdata[19] = found_nonce;
            submit_solution(work, found_hash, mythr);
            n = found_nonce;
            *hashes_done = (uint64_t)(n - first_nonce + 1);
            return 0;
        }

        // advance
        n += current_batch;
    }

    pdata[19] = n;
    *hashes_done = n - first_nonce + 1;
    return 0;

cpu_path:
    // fallback to CPU loop if OpenCL path unavailable or errored
    ;
#endif // USE_OPENCL

    // CPU loop
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
