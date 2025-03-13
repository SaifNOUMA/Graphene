
#include "../types.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include "../umac/common.h"

static int bench_xor(u32 bench_iterations, u32 datalen, u32 batch_size, double *cpu_time);

int main(int argc, char **argv)
{
    u32 batch_size = 1;
    double cpu_time[128][128];
    u32 bench_iterations = 1000;

    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { batch_size = atoi(argv[2]); }

    u32 datalens[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};

    // for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    {
        if (bench_xor(bench_iterations, datalens[i], batch_size, &cpu_time[0][i]) != 0) { return -1; }
        // if (bench_xor(bench_iterations, datalens[i], batch_size, &cpu_time[0][i]) != 0) { return -1; }
    }
    save_to_csv("bench_xor.csv", 1, sizeof(datalens)/sizeof(u32), cpu_time);

    return 0;
}

// implementation
static int bench_xor(u32 bench_iterations, u32 datalen, u32 batch_size, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    u32 outlen = 16;
    u32 keylen;

    u8 *in1, *in2;

    in1  = (u8*) malloc(datalen);
    in2  = (u8*) malloc(datalen);

    if (RAND_bytes(in1, datalen) != 1) { return -1; }
    if (RAND_bytes(in2, datalen) != 1) { return -1; }

    _cpu_time = 0;

    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (u32 bi = 0; bi < batch_size; bi++) {
            for (u32 i = 0; i < datalen; i++)
            {
                in1[i] ^= in2[i];
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    }

    printf("XOR(inlen=%4u, batch_size=%4u) = %.0f ms\n", datalen, batch_size, _cpu_time / bench_iterations);
    *cpu_time = _cpu_time / bench_iterations;

    free(in1);
    free(in2);

    return 0;
}
