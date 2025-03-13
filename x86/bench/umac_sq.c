
#include "../types.h"
#include "../prf/rng_byte.h"
#include "../umac/sq_umac.h"
#include <openssl/rand.h>

int bench_umac_sqh(u32 bench_iterations, u32 datalen, u32 prime_bits, double *cpu_time);
int bench_umac_sqh_batch(u32 bench_iterations, u32 batch_size, u32 datalen, u32 prime_bits, double *cpu_time);

int main(int argc, char **argv)
{
    u32 batch_size = 100;
    u32 bench_iterations = 1000;
    double cpu_time[128][128];
    // u32 prime_bits_set[] = {64, 80, 128, 256};
    u32 prime_bits_set[] = {128};
    u32 datalens[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024};

    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { batch_size = atoi(argv[2]); }

    for (u32 idx = 0; idx < sizeof(prime_bits_set)/sizeof(u32); idx++)
    {
        // for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
        // {
        //     if (bench_umac_sqh(bench_iterations, datalens[i], prime_bits_set[idx], &cpu_time[idx][i]) != 0) { return -1; }
        // }

        for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
        {
            // if (bench_umac_sqh_batch(bench_iterations, batch_size, datalens[i], prime_bits_set[idx], &cpu_time) != 0) { return -1; }
            if (bench_umac_sqh_batch(bench_iterations, datalens[i], datalens[3], prime_bits_set[idx], &cpu_time) != 0) { return -1; }
        }
    }

    save_to_csv("bench_umac_sqh.csv", sizeof(prime_bits_set)/sizeof(u32), sizeof(datalens)/sizeof(u32), cpu_time);

    return 0;
}

// implementation
int bench_umac_sqh(u32 bench_iterations, u32 datalen, u32 prime_bits, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    SQ_UMAC_CTX umac_ctx;
    u8 *in, *out;
    u32 outlen, prime_bytes = (prime_bits+7)/8;
    u32 padded_inlen = (datalen + prime_bytes - 1) / prime_bytes * prime_bytes;
    u32 blocks = padded_inlen / prime_bytes;
    in  = (u8*) malloc(datalen);
    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (sq_umac_init(&umac_ctx, prime_bits) != 0) { return -1; }

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++) {
        // clock_gettime(CLOCK_MONOTONIC, &t0);

        if (sq_umac_memory(in, datalen, out, &outlen, &umac_ctx, &_cpu_time) != 0) { return -1; }

        // clock_gettime(CLOCK_MONOTONIC, &t1);
        // _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }

    printf("SQ_UMAC(prime_bits=%3u, prime_bytes=%3u, inlen=%4u, padded_inlen=%4u, blocks=%4u) = %.6f ms\n", prime_bits, prime_bytes, datalen, padded_inlen, blocks, _cpu_time / bench_iterations);
    *cpu_time = _cpu_time / bench_iterations * 1e6;
    
    free(in);
    free(out);
    sq_umac_free(&umac_ctx);
    return 0;
}

int bench_umac_sqh_batch(u32 bench_iterations, u32 batch_size, u32 datalen, u32 prime_bits, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    SQ_UMAC_CTX umac_ctx;
    u8 *in, *out;
    u32 outlen, prime_bytes = (prime_bits+7)/8;
    u32 padded_inlen = (datalen + prime_bytes - 1) / prime_bytes * prime_bytes;
    u32 blocks = padded_inlen / prime_bytes;
    in  = (u8*) malloc(datalen);
    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (sq_umac_init(&umac_ctx, prime_bits) != 0) { return -1; }

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++) {
        // clock_gettime(CLOCK_MONOTONIC, &t0);
        for (u32 i = 0; i < batch_size; i++) {
            if (sq_umac_memory(in, datalen, out, &outlen, &umac_ctx, &_cpu_time) != 0) { return -1; }
        }
        // clock_gettime(CLOCK_MONOTONIC, &t1);
        // _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }

    printf("SQ_UMAC_BATCH(prime_bits=%3u, prime_bytes=%3u, inlen=%4u, padded_inlen=%4u, blocks=%4u, batch_size=%4u) = %.0f ms\n", prime_bits, prime_bytes, datalen, padded_inlen, blocks, _cpu_time / bench_iterations, batch_size);
    *cpu_time = _cpu_time / bench_iterations;
    
    free(in);
    free(out);
    sq_umac_free(&umac_ctx);
    return 0;
}
