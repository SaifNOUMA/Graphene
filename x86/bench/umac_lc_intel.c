
#include "../umac/common.h"
#include <time.h>
#define bytelength 8
#define bitlength 64

void print_uint128(__uint128_t value);
void uint128_to_byte_array(__uint128_t value, unsigned char *array);
int lc_umac_64bit_intel(u32 bench_iterations, u32 datalen, double *cpu_time);
__uint128_t byte_array_to_uint128(const unsigned char *array);

int main(int argc, char **argv)
{

    u32 bench_iterations = 1000;
    u32 datalen = 1024;
    double cpu_time[128][128];

    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { datalen = atoi(argv[2]); }

    u32 datalens[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024};

    for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    {
        if (lc_umac_64bit_intel(bench_iterations, datalens[i], &cpu_time[0][i]) != 0) { return -1; }
    }

    save_to_csv("bench_umac_lc_intel.csv", 1, sizeof(datalens)/sizeof(u32), cpu_time);

    return 0;
}

void print_uint128(__uint128_t value) {
    // Split the 128-bit value into high and low 64-bit partss
    uint64_t high = value >> 64;
    uint64_t low = (uint64_t)value;

    // Print the 128-bit value as a hexadecimal number
    if (high == 0) {
        printf("%" PRIu64 "\n", low);
    } else {
        printf("%" PRIu64 "%018" PRIu64 "\n", high, low);
    }
}

void uint128_to_byte_array(__uint128_t value, unsigned char *array) {
    memcpy(array, &value, 16);
}

__uint128_t byte_array_to_uint128(const unsigned char *array) {
    __uint128_t value = 0;
    for (int i = 0; i < 16; ++i) {
        value = (value << 8) | array[15-i];
    }
    return value;
}

int lc_umac_64bit_intel(u32 bench_iterations, u32 datalen, double *cpu_time)
{
    double _cpu_time = 0;
    struct timespec start, end;
    u32 outlen, blocks = (datalen + 8 - 1) / 8;
    u8 *in, *out;
    __uint128_t a[blocks], b[blocks], p = 1000470615399153403, in_tmp, out_tmp;
    u8 p_bytes[16] = {0}, a_bytes[16], b_bytes[16];

    for (u32 i = 0; i < blocks; i++) {
        RAND_bytes(a_bytes, 16);
        RAND_bytes(b_bytes, 16);
        a[i] = byte_array_to_uint128(a_bytes) % p;
        b[i] = byte_array_to_uint128(b_bytes) % p;
    }

    in = (u8*) malloc(blocks * bytelength);

    in_tmp = byte_array_to_uint128(in + 0 * bytelength);
    // Execute the test
    for (u32 iter = 0 ; iter < bench_iterations ; iter++) {

        clock_gettime(CLOCK_MONOTONIC, &start);

        for (u32 block = 0 ; block < blocks ; block++) {
            in_tmp = byte_array_to_uint128(in + block * bytelength);
            out_tmp = (a[block] * in_tmp + b[block]) % p;
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        _cpu_time += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6;
    }

    // Print the results
    printf("LC_UMAC_INTEL(#bits=%3u,inlen=%4u,blocks=%4u) = %.6f ms\n", 64, datalen, blocks, _cpu_time / bench_iterations);
    *cpu_time = _cpu_time * 1e6 / bench_iterations;
    // Free memory
    free(in);
    return 0;
}  // lc_umac_test