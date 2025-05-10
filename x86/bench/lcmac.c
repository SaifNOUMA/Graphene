
#include "rng.h"
#include "rng_byte.h"
#include "lc_umac.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

int bench_umac_lc(u32 bench_iterations, u32 datalen, u32 prime_bits, double *cpu_time);
int bench_umac_lc_batch(u32 bench_iterations, u32 batch_size, u32 datalen, u32 prime_bits, double *cpu_time);

int main(int argc, char **argv)
{
    u32 batch_size = 100;
    double cpu_time[128][128];
    u32 bench_iterations = 1000;

    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { batch_size = atoi(argv[2]); }

    u32 prime_bits_set[] = {128};
    u32 datalens[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};

    for (u32 idx = 0; idx < sizeof(prime_bits_set)/sizeof(u32); idx++)
    {
        cpu_time[idx][0] = prime_bits_set[idx];
        for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
        {
            if (bench_umac_lc(bench_iterations, datalens[i], prime_bits_set[idx], &cpu_time[idx][i+1]) != 0) { return -1; }
        }
    }

    // for (u32 idx = 0; idx < sizeof(prime_bits_set)/sizeof(u32); idx++)
    // {
    //     cpu_time[idx][0] = prime_bits_set[idx];
    //     for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    //     {
    //         if (bench_umac_lc_batch(bench_iterations, datalens[i], datalens[9], prime_bits_set[idx], &cpu_time[idx][i+1]) != 0) { return -1; }
    //     }
    // }

    save_to_csv("bench_umac_lc.csv", sizeof(prime_bits_set)/sizeof(u32), sizeof(datalens)/sizeof(u32) + 1, cpu_time);

    return 0;
}

// implementation
int bench_umac_lc(u32 bench_iterations, u32 datalen, u32 prime_bits, double *cpu_time)
{
    u8 *in, *out;
    u32 outlen, prime_bytes = (prime_bits+7)/8;
    u32 padded_inlen = (datalen + prime_bytes - 1) / prime_bytes * prime_bytes;
    u32 blocks = padded_inlen / prime_bytes;
    in  = (u8*) malloc(padded_inlen);
    out = (u8*) malloc(prime_bytes);
    memset(in, 0, padded_inlen);
    if (RAND_bytes(in, datalen) != 1) { return -1; }

    double _cpu_time;
    struct timespec t0, t1;
    LC_UMAC_CTX umac_ctx;
    gmp_randstate_t state;

    mpz_t tmp_mpz; // temporary variable for calculations

    gmp_randinit_default(state);
    mpz_init(umac_ctx.a);
    mpz_init(umac_ctx.b);
    mpz_init(umac_ctx.p);
    mpz_init(umac_ctx.in_mpz);
    mpz_init(umac_ctx.out_mpz);
    mpz_init(umac_ctx.tmp_mpz);
    mpz_init(tmp_mpz); // initialize the temporary variable

    umac_ctx.prime_bits = prime_bits;
    umac_ctx.prime_bytes = (prime_bits+7)/8;
    rng_prime(umac_ctx.p, prime_bits);
    mpz_set_ui(umac_ctx.out_mpz, 0);
    mpz_urandomb(umac_ctx.a, state, prime_bits);
    mpz_urandomb(umac_ctx.b, state, prime_bits);
    mpz_urandomb(umac_ctx.in_mpz, state, prime_bits);
    mpz_urandomb(tmp_mpz, state, 3);
    mpz_set_d(tmp_mpz, 65537); // initialize tmp_mpz to zero
    mpz_mod(umac_ctx.a, umac_ctx.a, umac_ctx.p);
    mpz_mod(umac_ctx.b, umac_ctx.b, umac_ctx.p);
    gmp_randclear(state);

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++) {

        clock_gettime(CLOCK_MONOTONIC, &t0);

        u32 blocks = (datalen + umac_ctx.prime_bytes - 1) / umac_ctx.prime_bytes;

        for (u32 block = 0; block < blocks-1; block++) {
            size_t _inlen = (size_t)umac_ctx.prime_bytes;
            mpz_import(umac_ctx.in_mpz, _inlen, 1, 1, 0, 0, in+block*umac_ctx.prime_bytes);

            clock_gettime(CLOCK_MONOTONIC, &t0);
            mpz_mul(umac_ctx.tmp_mpz, umac_ctx.a, umac_ctx.in_mpz);
            mpz_add(umac_ctx.tmp_mpz, umac_ctx.tmp_mpz, umac_ctx.b);
            mpz_add(umac_ctx.out_mpz, umac_ctx.out_mpz, umac_ctx.tmp_mpz);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
        }

        size_t _inlen = (size_t)datalen-(blocks-1)*umac_ctx.prime_bytes;
        mpz_import(umac_ctx.in_mpz, _inlen, 1, 1, 0, 0, in+(blocks-1)*umac_ctx.prime_bytes);

        clock_gettime(CLOCK_MONOTONIC, &t0);
        mpz_mul(umac_ctx.tmp_mpz, umac_ctx.in_mpz, umac_ctx.a);
        mpz_add(umac_ctx.out_mpz, umac_ctx.tmp_mpz, umac_ctx.tmp_mpz);

        mpz_add(umac_ctx.out_mpz, umac_ctx.out_mpz, umac_ctx.b);
        mpz_mod(umac_ctx.out_mpz, umac_ctx.out_mpz, umac_ctx.p);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);

        size_t _outlen;
        mpz_export(out, &_outlen, 1, 1, 0, 0, umac_ctx.out_mpz);
    }

    printf("LC_UMAC(prime_bits=%3u, prime_bytes=%3u, inlen=%4u, padded_inlen=%4u, blocks=%4u) = %.0f ns\n", prime_bits, prime_bytes, datalen, padded_inlen, blocks, _cpu_time / bench_iterations);
    *cpu_time = _cpu_time / bench_iterations;
    
    free(in);
    free(out);
    mpz_clear(umac_ctx.a);
    mpz_clear(umac_ctx.b);
    mpz_clear(umac_ctx.p);
    mpz_clear(umac_ctx.in_mpz);
    mpz_clear(umac_ctx.out_mpz);
    mpz_clear(umac_ctx.tmp_mpz);
    return 0;
}

// implementation
int bench_umac_lc_batch(u32 bench_iterations, u32 batch_size, u32 datalen, u32 prime_bits, double *cpu_time)
{
    u8 *in, *out;
    u32 outlen, prime_bytes = (prime_bits+7)/8;
    u32 padded_inlen = (datalen + prime_bytes - 1) / prime_bytes * prime_bytes;
    u32 blocks = padded_inlen / prime_bytes;
    in  = (u8*) malloc(padded_inlen);
    out = (u8*) malloc(prime_bytes);
    memset(in, 0, padded_inlen);
    if (RAND_bytes(in, datalen) != 1) { return -1; }

    double _cpu_time;
    struct timespec t0, t1;
    LC_UMAC_CTX umac_ctx;
    gmp_randstate_t state;

    gmp_randinit_default(state);
    mpz_init(umac_ctx.a);
    mpz_init(umac_ctx.b);
    mpz_init(umac_ctx.p);
    mpz_init(umac_ctx.in_mpz);
    mpz_init(umac_ctx.out_mpz);
    mpz_init(umac_ctx.tmp_mpz);

    umac_ctx.prime_bits = prime_bits;
    umac_ctx.prime_bytes = (prime_bits+7)/8;
    rng_prime(umac_ctx.p, prime_bits);
    mpz_set_ui(umac_ctx.out_mpz, 0);
    mpz_urandomb(umac_ctx.a, state, prime_bits);
    mpz_urandomb(umac_ctx.b, state, prime_bits);
    mpz_urandomb(umac_ctx.in_mpz, state, prime_bits);
    mpz_mod(umac_ctx.a, umac_ctx.a, umac_ctx.p);
    mpz_mod(umac_ctx.b, umac_ctx.b, umac_ctx.p);
    gmp_randclear(state);

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++) {

        for (u32 item = 0; item < batch_size; item++) {
            if (RAND_bytes(in, datalen) != 1) { return -1; }

            clock_gettime(CLOCK_MONOTONIC, &t0);

            u32 blocks = (datalen + umac_ctx.prime_bytes - 1) / umac_ctx.prime_bytes;

            for (u32 block = 0; block < blocks-1; block++) {
                size_t _inlen = (size_t)umac_ctx.prime_bytes;
                mpz_import(umac_ctx.in_mpz, _inlen, 1, 1, 0, 0, in+block*umac_ctx.prime_bytes);

                clock_gettime(CLOCK_MONOTONIC, &t0);
                mpz_mul(umac_ctx.tmp_mpz, umac_ctx.a, umac_ctx.in_mpz);
                mpz_add(umac_ctx.out_mpz, umac_ctx.out_mpz, umac_ctx.tmp_mpz);
                clock_gettime(CLOCK_MONOTONIC, &t1);
                _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
            }

            size_t _inlen = (size_t)datalen-(blocks-1)*umac_ctx.prime_bytes;
            mpz_import(umac_ctx.in_mpz, _inlen, 1, 1, 0, 0, in+(blocks-1)*umac_ctx.prime_bytes);

            clock_gettime(CLOCK_MONOTONIC, &t0);
            mpz_mul(umac_ctx.tmp_mpz, umac_ctx.a, umac_ctx.in_mpz);
            mpz_add(umac_ctx.out_mpz, umac_ctx.out_mpz, umac_ctx.tmp_mpz);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
        }

        clock_gettime(CLOCK_MONOTONIC, &t0);
        mpz_add(umac_ctx.out_mpz, umac_ctx.out_mpz, umac_ctx.b);
        mpz_mod(umac_ctx.out_mpz, umac_ctx.out_mpz, umac_ctx.p);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);

        size_t _outlen;
        mpz_export(out, &_outlen, 1, 1, 0, 0, umac_ctx.out_mpz);
    }

    printf("LC_UMAC_BATCH(prime_bits=%3u, prime_bytes=%3u, inlen=%4u, padded_inlen=%4u, blocks=%4u, batch_size=%4u) = %.0f ms\n", prime_bits, prime_bytes, datalen, padded_inlen, blocks, batch_size, _cpu_time / bench_iterations);
    *cpu_time = _cpu_time / bench_iterations;
    
    free(in);
    free(out);
    mpz_clear(umac_ctx.a);
    mpz_clear(umac_ctx.b);
    mpz_clear(umac_ctx.p);
    mpz_clear(umac_ctx.in_mpz);
    mpz_clear(umac_ctx.out_mpz);
    mpz_clear(umac_ctx.tmp_mpz);
    return 0;
}
