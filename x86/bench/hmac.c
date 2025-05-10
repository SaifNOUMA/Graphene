
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <gcrypt.h>
#include <libtomcrypt/tomcrypt.h>
#include "common.h"

typedef struct {
    u32 outlen;
    u32 keylen;
    const char *name;
    u32 (*hmac)(u8*, u32, u8*, u32, u8*);
} test_hmac_t;

u32 openssl_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);
u32 openssl_hmac_sha_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hmac_sha_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);

u32 openssl_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);
u32 openssl_hmac_blake2b_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hmac_blake2b_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);

u32 gcrypt_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hmac_sha_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hmac_blake2b_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);

static int bench_hmac(u32 bench_iterations, u32 datalen, test_hmac_t test_hmac, double *cpu_time);

static test_hmac_t test_hmacs[] = {
    // {32, 32, "libtomcrypt_hmac_sha_256    ", libtomcrypt_hmac_sha_256},
    // {32, 32, "libtomcrypt_hmac_blake2s_256", libtomcrypt_hmac_blake2s_256},
    // {64, 64, "libtomcrypt_hmac_sha_512    ", libtomcrypt_hmac_sha_512},
    // {64, 64, "libtomcrypt_hmac_blake2b_512", libtomcrypt_hmac_blake2b_512},

    {32, 32, "openssl_hmac_sha_256        ", openssl_hmac_sha_256},
    // {32, 32, "openssl_hmac_blake2s_256    ", openssl_hmac_blake2s_256},
    // {64, 64, "openssl_hmac_sha_512        ", openssl_hmac_sha_512},
    // {64, 64, "openssl_hmac_blake2b_512    ", openssl_hmac_blake2b_512},

    // {32, 32, "gcrypt_hmac_sha_256         ", gcrypt_hmac_sha_256},
    // {32, 32, "gcrypt_hmac_blake2s_256     ", gcrypt_hmac_blake2s_256},
    // {64, 64, "gcrypt_hmac_sha_512         ", gcrypt_hmac_sha_512},
    // {64, 64, "gcrypt_hmac_blake2b_512     ", gcrypt_hmac_blake2b_512},
};

int main(int argc, char **argv)
{
    u32 bench_iterations = 1000;
    u32 datalen = 1024;
    double cpu_time[128][128];

    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { datalen = atoi(argv[2]); }

    u32 datalens[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};

    // register hashes for libtomcrypt
    register_hash(&sha256_desc);
    register_hash(&sha512_desc);
    register_hash(&blake2s_256_desc);
    register_hash(&blake2b_512_desc);

    for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    {
        for (u32 idx = 0; idx < sizeof(test_hmacs)/sizeof(test_hmac_t); idx++) {
            if (bench_hmac(bench_iterations, datalens[i], test_hmacs[idx], &cpu_time[idx][i]) != 0) { return -1; }
        }
    }

    save_to_csv("bench_hmac.csv", sizeof(test_hmacs)/sizeof(test_hmac_t), sizeof(datalens)/sizeof(u32), cpu_time);

    return 0;
}

// implementation
static int bench_hmac(u32 bench_iterations, u32 datalen, test_hmac_t test_hmac, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    u32 outlen = 16;
    u32 keylen;

    u8 *in, *out, *key;

    keylen = test_hmac.keylen;
    outlen = test_hmac.outlen;

    in  = (u8*) malloc(datalen);
    out = (u8*) malloc(test_hmac.outlen);
    key = (u8*) malloc(keylen);

    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (RAND_bytes(key, keylen) != 1) { return -1; }

    _cpu_time = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        if (test_hmac.hmac(key, keylen, in, datalen, out) != 0) { return -1; }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);

    printf("HMAC(%11s,inlen=%4u) = %.0f ns\n", test_hmac.name, datalen, _cpu_time / bench_iterations);
    *cpu_time = _cpu_time * 1e6 / bench_iterations;

    free(in);
    free(out);
    free(key);

    return 0;
}

u32 gcrypt_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 32;

    gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    gcry_md_setkey(hd, key, keylen);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_SHA256), outlen);
    gcry_md_close(hd);

    return 0;
}

u32 gcrypt_hmac_sha_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 64;

    gcry_md_open(&hd, GCRY_MD_SHA512, 0);
    gcry_md_setkey(hd, key, keylen);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_SHA512), outlen);
    gcry_md_close(hd);

    return 0;
}

u32 gcrypt_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 32;

    gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0);
    gcry_md_setkey(hd, key, keylen);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_BLAKE2S_256), outlen);
    gcry_md_close(hd);

    return 0;
}

u32 gcrypt_hmac_blake2b_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 64;

    gcry_md_open(&hd, GCRY_MD_BLAKE2B_512, 0);
    gcry_md_setkey(hd, key, keylen);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_BLAKE2B_512), outlen);
    gcry_md_close(hd);

    return 0;
}

u32 openssl_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen;
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) { return -1; }

    if (HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL) != 1) {
        HMAC_CTX_free(ctx);
        return -1;
    }

    if (HMAC_Update(ctx, data, datalen) != 1) {
        HMAC_CTX_free(ctx);
        return -1;
    }

    if (HMAC_Final(ctx, out, &outlen) != 1) {
        HMAC_CTX_free(ctx);
        return -1;
    }

    HMAC_CTX_free(ctx);

    return 0;
}

u32 openssl_hmac_sha_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen;

    if (HMAC(EVP_sha512(), key, keylen, data, datalen, out, &outlen) == NULL) { return -1; }

    return 0;
}

u32 openssl_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen;

    if (HMAC(EVP_blake2s256(), key, keylen, data, datalen, out, &outlen) == NULL) { return -1; }

    return 0;
}

u32 openssl_hmac_blake2b_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen;

    if (HMAC(EVP_blake2b512(), key, keylen, data, datalen, out, &outlen) == NULL) { return -1; }

    return 0;
}

u32 libtomcrypt_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    hmac_state state;
    unsigned long outlen = 32;

    if (hmac_init(&state, find_hash("sha256"), key, keylen) != CRYPT_OK) { return -1; }
    if (hmac_process(&state, data, datalen) != CRYPT_OK) { return -1; } 
    if (hmac_done(&state, out, &outlen) != CRYPT_OK) { return -1; }

    return 0;
}

u32 libtomcrypt_hmac_sha_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    hmac_state state;
    unsigned long outlen = 64;

    if (hmac_init(&state, find_hash("sha512"), key, keylen) != CRYPT_OK) { return -1; }
    if (hmac_process(&state, data, datalen) != CRYPT_OK) { return -1; }
    if (hmac_done(&state, out, &outlen) != CRYPT_OK) { return -1; }

    return 0;
}

u32 libtomcrypt_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    hmac_state state;
    unsigned long outlen = 32;

    if (hmac_init(&state, find_hash("blake2s-256"), key, keylen) != CRYPT_OK) { return -1; }
    if (hmac_process(&state, data, datalen) != CRYPT_OK) { return -1; }
    if (hmac_done(&state, out, &outlen) != CRYPT_OK) { return -1; }

    return 0;
}

u32 libtomcrypt_hmac_blake2b_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    hmac_state state;
    unsigned long outlen = 64;

    if (hmac_init(&state, find_hash("blake2b-512"), key, keylen) != CRYPT_OK) { return -1; }
    if (hmac_process(&state, data, datalen) != CRYPT_OK) { return -1; }
    if (hmac_done(&state, out, &outlen) != CRYPT_OK) { return -1; }

    return 0;
}
