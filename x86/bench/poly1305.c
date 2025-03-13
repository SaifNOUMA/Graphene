
#include "../poly1305/poly1305aes/poly1305_53.h"
#include "../umac/common.h"
#include "../prf/rng_byte.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <gcrypt.h>

static int bench_poly1305_ssl(u32 bench_iterations, u32 datalen, double *cpu_time);
static int bench_poly1305_gcrypt(u32 bench_iterations, u32 datalen, double *cpu_time);
static int bench_poly1305_ref(u32 bench_iterations, u32 datalen, double *cpu_time);
static int bench_poly1305_aes_ssl(u32 bench_iterations, u32 batch_size, u32 datalen, double *cpu_time);
static int bench_poly1305_aes_gcrypt(u32 bench_iterations, u32 batch_size, u32 datalen, double *cpu_time);
static int bench_poly1305_aes_ref(u32 bench_iterations, u32 batch_size, u32 datalen, double *cpu_time);

int main(int argc, char **argv)
{
    u32 bench_iterations = 1000;
    u32 datalen = 1024;
    u32 batch_size = 100;
    double cpu_time[128][128];

    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { datalen = atoi(argv[2]); }
    if (argc > 3) { batch_size = atoi(argv[3]); }

    u32 datalens[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};

    for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    {
        if (bench_poly1305_ssl(bench_iterations, datalens[i], &cpu_time[0][i]) != 0) { return -1; }
        // if (bench_poly1305_gcrypt(bench_iterations, datalens[i], &cpu_time[1][i]) != 0) { return -1; }
        // if (bench_poly1305_ref(bench_iterations, datalens[i], &cpu_time[2][i]) != 0) { return -1; }
    }

    // for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    // {
        // if (bench_poly1305_aes_ssl(bench_iterations, batch_size, datalens[i], &cpu_time[2][i]) != 0) { return -1; }
    //     if (bench_poly1305_aes_ref(bench_iterations, batch_size, datalens[i], &cpu_time[3][i]) != 0) { return -1; }
    // }

    save_to_csv("bench_poly1305.csv", 3, sizeof(datalens)/sizeof(u32), cpu_time);

    return 0;
}

// implementation
static int bench_poly1305_ssl(u32 bench_iterations, u32 datalen, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    u32 outlen = 16;
    u32 keylen = 32;
    u32 len;
    u8 *in, *out, key[keylen];
    EVP_MAC_CTX *poly_mac_ctx;
    EVP_MAC *poly_mac;
    in  = (u8*) malloc(datalen);
    out = (u8*) malloc(outlen);

    poly_mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if (poly_mac == NULL) { return -1; }

    poly_mac_ctx = EVP_MAC_CTX_new(poly_mac);

    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (RAND_bytes(key, keylen) != 1) { return -1; }

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        clock_gettime(CLOCK_REALTIME, &t0);

        if (EVP_MAC_init(poly_mac_ctx, key, keylen, NULL) != 1) { return -1; }
        if (EVP_MAC_update(poly_mac_ctx, in, datalen) != 1) { return -1; }
        if (EVP_MAC_final(poly_mac_ctx, out, NULL, 16) != 1) { return -1; }

        clock_gettime(CLOCK_REALTIME, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }

    *cpu_time = _cpu_time * 1e6 / bench_iterations;
    printf("POLY1305 (SSL, inlen=%4u) : %.6f ms\n", datalen, _cpu_time / bench_iterations);

    free(in);
    free(out);
    EVP_MAC_free(poly_mac);
    EVP_MAC_CTX_free(poly_mac_ctx);
    return 0;
}

static int bench_poly1305_aes_ssl(u32 bench_iterations, u32 batch_size, u32 datalen, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    u32 outlen = 16;
    u32 keylen = 32;
    u32 len;
    u8 *in, *out, key[keylen];
    EVP_MAC *poly_mac;
    EVP_MAC_CTX *poly_mac_ctx;
    in  = (u8*) malloc(datalen);
    out = (u8*) malloc(outlen);

    poly_mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if (poly_mac == NULL) { return -1; }
    poly_mac_ctx = EVP_MAC_CTX_new(poly_mac);
    if (poly_mac_ctx == NULL) { return -1; }

    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (RAND_bytes(key, keylen) != 1) { return -1; }

    RNG_BYTE_CTX rng_ctx;
    if (rng_byte_init("aes-128-ctr", 16, &rng_ctx) != 0) { return -1; }

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        clock_gettime(CLOCK_REALTIME, &t0);

        for (u32 epoch = 0; epoch < batch_size; epoch++)
        {
            if (rng_byte_exec(key+16, 16, rng_ctx) != 0) { return -1; }

            if (EVP_MAC_init(poly_mac_ctx, key, keylen, NULL) != 1) { return -1; }
            if (EVP_MAC_update(poly_mac_ctx, in, datalen) != 1) { return -1; }
            if (EVP_MAC_final(poly_mac_ctx, out, NULL, 16) != 1) { return -1; }
        }

        clock_gettime(CLOCK_REALTIME, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }

    *cpu_time = _cpu_time / bench_iterations;
    printf("POLY1305 (SSL, inlen=%4u, batch_size=%4u) : %.6f ms\n", datalen, batch_size, _cpu_time / bench_iterations);

    free(in);
    free(out);
    EVP_MAC_free(poly_mac);
    EVP_MAC_CTX_free(poly_mac_ctx);
    rng_byte_clear(&rng_ctx);
    return 0;
}

static int bench_poly1305_gcrypt(u32 bench_iterations, u32 datalen, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    size_t outlen = 16;
    u32 keylen = 32;
    u32 len;
    u8 *in, *out, key[keylen];
    gcry_mac_hd_t poly_mac_ctx;
    gcry_error_t err;
    in  = (u8*) malloc(datalen);
    out = (u8*) malloc(outlen);

    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (RAND_bytes(key, keylen) != 1) { return -1; }

    err = gcry_mac_open(&poly_mac_ctx, GCRY_MAC_POLY1305, 0, NULL);
    if (err) { return -1; }

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        clock_gettime(CLOCK_REALTIME, &t0);

        err = gcry_mac_setkey(poly_mac_ctx, key, keylen);
        if (err) { return -1; }
        err = gcry_mac_write(poly_mac_ctx, in, datalen);
        if (err) { return -1; }
        err = gcry_mac_read(poly_mac_ctx, out, &outlen);
        if (err) { return -1; }

        clock_gettime(CLOCK_REALTIME, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }

    *cpu_time = _cpu_time * 1e6 / bench_iterations;
    printf("POLY1305 (GPG, inlen=%4u) : %.6f ms\n", datalen, _cpu_time / bench_iterations);

    free(in);
    free(out);
    gcry_mac_close(poly_mac_ctx);
    return 0;
}

static int bench_poly1305_aes_gcrypt(u32 bench_iterations, u32 batch_size, u32 datalen, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    size_t outlen;
    u32 keylen = 32;
    u32 len;
    u8 *in, *out, key[keylen];
    gcry_mac_hd_t poly_mac_ctx;
    gcry_error_t err;
    in  = (u8*) malloc(datalen);
    out = (u8*) malloc(outlen);

    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (RAND_bytes(key, keylen) != 1) { return -1; }

    err = gcry_mac_open(&poly_mac_ctx, GCRY_MAC_POLY1305, 0, NULL);
    if (err) { return -1; }

    RNG_BYTE_CTX rng_ctx;
    if (rng_byte_init("aes-128-ctr", 16, &rng_ctx) != 0) { return -1; }

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        clock_gettime(CLOCK_REALTIME, &t0);

        for (u32 epoch = 0; epoch < batch_size; epoch++)
        {
            if (rng_byte_exec(key+16, 16, rng_ctx) != 0) { return -1; }

            err = gcry_mac_setkey(poly_mac_ctx, key, keylen);
            if (err) { return -1; }
            err = gcry_mac_write(poly_mac_ctx, in, datalen);
            if (err) { return -1; }
            err = gcry_mac_read(poly_mac_ctx, out, &outlen);
            if (err) { return -1; }
        }

        clock_gettime(CLOCK_REALTIME, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }

    *cpu_time = _cpu_time / bench_iterations;
    printf("POLY1305 (GPG, inlen=%4u, batch_size=%4u) : %.6f ms\n", datalen, batch_size, _cpu_time / bench_iterations);

    free(in);
    free(out);
    gcry_mac_close(poly_mac_ctx);
    return 0;
}

static int bench_poly1305_ref(u32 bench_iterations, u32 datalen, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    u32 outlen = 16;
    u32 keylen = 32;
    u32 len;
    u8 *in, *out, key[keylen], r[16], s[16];
    in  = (u8*) malloc(datalen);
    out = (u8*) malloc(outlen);

    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (RAND_bytes(key, keylen) != 1) { return -1; }

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        clock_gettime(CLOCK_REALTIME, &t0);

        memcpy(r, key, 16);
        memcpy(s, key+16, 16);
        poly1305_53(out, r, s, in, datalen);

        clock_gettime(CLOCK_REALTIME, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }

    *cpu_time = _cpu_time * 1e6 / bench_iterations;
    printf("POLY1305 (REF, inlen=%4u) : %.6f ms\n", datalen, _cpu_time / bench_iterations);

    free(in);
    free(out);
    return 0;
}

static int bench_poly1305_aes_ref(u32 bench_iterations, u32 batch_size, u32 datalen, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    RNG_BYTE_CTX rng_ctx;
    u32 outlen = 16;
    u32 keylen = 32;
    u32 len;
    u8 *in, *out, key[keylen], r[16], s[16];
    in  = (u8*) malloc(datalen);
    out = (u8*) malloc(outlen);


    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (RAND_bytes(key, keylen) != 1) { return -1; }
    memcpy(r, key, 16);
    if (rng_byte_init("aes-128-ctr", 16, &rng_ctx) != 0) { return -1; }

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        clock_gettime(CLOCK_REALTIME, &t0);

        for (u32 epoch = 0; epoch < batch_size; epoch++)
        {
            if (rng_byte_exec(s, 16, rng_ctx) != 0) { return -1; }
            memcpy(s, key+16, 16);
            poly1305_53(out, r, s, in, datalen);
        }

        clock_gettime(CLOCK_REALTIME, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }

    *cpu_time = _cpu_time / bench_iterations;
    printf("POLY1305 (SSL, inlen=%4u, batch_size=%4u) : %.6f ms\n", datalen, batch_size, _cpu_time / bench_iterations);

    free(in);
    free(out);
    rng_byte_clear(&rng_ctx);
    return 0;
}
