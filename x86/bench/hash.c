
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <gcrypt.h>
#include <libtomcrypt/tomcrypt.h>
#include "common.h"

typedef struct {
    u32 outlen;
    const char *name;
    u32 (*hash)(u8*, u32, u8*);
} test_hash_t;

u32 openssl_hash_sha_256(u8 *data, u32 datalen, u8 *out);
u32 openssl_hash_sha_512(u8 *data, u32 datalen, u8 *out);
u32 openssl_hash_blake2s_256(u8 *data, u32 datalen, u8 *out);
u32 openssl_hash_blake2b_512(u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hash_sha_256(u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hash_sha_512(u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hash_blake2s_256(u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hash_blake2b_512(u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hash_sha_256(u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hash_sha_512(u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hash_blake2s_256(u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hash_blake2b_512(u8 *data, u32 datalen, u8 *out);
static int bench_hash(test_hash_t test_hash, u32 bench_iterations, u32 datalen, double *cpu_time);

static test_hash_t test_hashes[] = {
    // {32, "libtomcrypt_hash_sha_256    ", libtomcrypt_hash_sha_256},
    // {64, "libtomcrypt_hash_sha_512    ", libtomcrypt_hash_sha_512},
    // {32, "libtomcrypt_hash_blake2s_256", libtomcrypt_hash_blake2s_256},
    // {64, "libtomcrypt_hash_blake2b_512", libtomcrypt_hash_blake2b_512},
    {32, "openssl_hash_sha_256        ", openssl_hash_sha_256},
    {64, "openssl_hash_sha_512        ", openssl_hash_sha_512},
    {32, "openssl_hash_blake2s_256    ", openssl_hash_blake2s_256},
    {64, "openssl_hash_blake2b_512    ", openssl_hash_blake2b_512},
    // {32, "gcrypt_hash_sha_256         ", gcrypt_hash_sha_256},
    // {64, "gcrypt_hash_sha_512         ", gcrypt_hash_sha_512},
    // {32, "gcrypt_hash_blake2s_256    ", gcrypt_hash_blake2s_256},
    // {64, "gcrypt_hash_blake2b_512    ", gcrypt_hash_blake2b_512},
};

int main(int argc, char **argv)
{
    u32 bench_iterations = 1000;
    u32 datalen = 1024;
    double cpu_time[128][128];

    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { datalen = atoi(argv[2]); }

    // u32 datalens[] = {8, 16, 32, 64, 128, 256};
    u32 datalens[] = {16, 32, 64, 128, 256, 512, 1024};

    for (u32 idx = 0 ; idx < sizeof(test_hashes)/sizeof(test_hash_t) ; idx++)
    {
        for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
        {
            if (bench_hash(test_hashes[idx], bench_iterations, datalens[i], &cpu_time[idx][i]) != 0) { return -1; }
        }
    }

    save_to_csv("bench_hash.csv", sizeof(test_hashes)/sizeof(test_hash_t), sizeof(datalens)/sizeof(u32), cpu_time);

    return 0;
}

// implementation
static int bench_hash(test_hash_t test_hash, u32 bench_iterations, u32 datalen, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    u32 outlen = 16;

    u8 *in, *out;
    in  = (u8*) malloc(datalen);
    out = (u8*) malloc(test_hash.outlen);
    if (RAND_bytes(in, datalen) != 1) { return -1; }
    _cpu_time = 0;

    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        clock_gettime(CLOCK_MONOTONIC, &t0);

        if (test_hash.hash(in, datalen, out) != test_hash.outlen) { return -1; }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    }
    printf("%s(inlen=%4u) = %.0f ns\n", test_hash.name, datalen, _cpu_time / bench_iterations);

    *cpu_time = _cpu_time / bench_iterations;

    free(in);
    free(out);
    return 0;
}

u32 gcrypt_hash_blake2b_512(u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 64;

    gcry_md_open(&hd, GCRY_MD_BLAKE2B_512, 0);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_BLAKE2B_512), outlen);
    gcry_md_close(hd);

    return outlen;
}

u32 gcrypt_hash_blake2s_256(u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 32;

    gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_BLAKE2S_256), outlen);
    gcry_md_close(hd);

    return outlen;
}

u32 gcrypt_hash_sha_512(u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 64;

    gcry_md_open(&hd, GCRY_MD_SHA512, 0);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_SHA512), outlen);
    gcry_md_close(hd);

    return outlen;
}

u32 gcrypt_hash_sha_256(u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 32;

    gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_SHA256), outlen);
    gcry_md_close(hd);

    return outlen;
}


u32 openssl_hash_sha_256(u8 *data, u32 datalen, u8 *out)
{
    u32 outlen = 0;
    const EVP_MD *md;
    EVP_MD_CTX *mdctx;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, datalen);
    EVP_DigestFinal_ex(mdctx, out, &outlen);
    EVP_MD_CTX_free(mdctx);

    return outlen;
}

u32 openssl_hash_sha_512(u8 *data, u32 datalen, u8 *out)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    u32 outlen = 0;

    md = EVP_sha512();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, datalen);
    EVP_DigestFinal_ex(mdctx, out, &outlen);
    EVP_MD_CTX_free(mdctx);

    return outlen;
}

u32 libtomcrypt_hash_sha_256(u8 *data, u32 datalen, u8 *out)
{
    hash_state md;
    u32 outlen = 32;

    sha256_init(&md);
    sha256_process(&md, data, datalen);
    sha256_done(&md, out);

    return outlen;
}

u32 libtomcrypt_hash_sha_512(u8 *data, u32 datalen, u8 *out)
{
    hash_state md;
    u32 outlen = 64;

    sha512_init(&md);
    sha512_process(&md, data, datalen);
    sha512_done(&md, out);

    return outlen;
}

u32 openssl_hash_blake2s_256(u8 *data, u32 datalen, u8 *out)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    u32 outlen = 0;

    md = EVP_blake2s256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, datalen);
    EVP_DigestFinal_ex(mdctx, out, &outlen);
    EVP_MD_CTX_free(mdctx);

    return outlen;
}

u32 openssl_hash_blake2b_512(u8 *data, u32 datalen, u8 *out)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    u32 outlen = 0;

    md = EVP_blake2b512();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, datalen);
    EVP_DigestFinal_ex(mdctx, out, &outlen);
    EVP_MD_CTX_free(mdctx);

    return outlen;
}

u32 libtomcrypt_hash_blake2s_256(u8 *data, u32 datalen, u8 *out)
{
    hash_state md;
    u32 outlen = 32;

    blake2s_init(&md, outlen, NULL, 0);
    blake2s_process(&md, data, datalen);
    blake2s_done(&md, out);

    return outlen;
}

u32 libtomcrypt_hash_blake2b_512(u8 *data, u32 datalen, u8 *out)
{
    hash_state md;
    u32 outlen = 64;

    blake2b_init(&md, outlen, NULL, 0);
    blake2b_process(&md, data, datalen);
    blake2b_done(&md, out);

    return outlen;
}
