
#include "../types.h"
#include <gcrypt.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <libtomcrypt/tomcrypt.h>

typedef struct {
    u32 outlen;
    const char *name;
    u32 (*hash)(u8*, u32, u8*);
} test_hash_t;

u32 openssl_hash_sha_256(u8 *data, u32 datalen, u8 *out);
u32 openssl_hash_sha_512(u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hash_sha_256(u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hash_sha_512(u8 *data, u32 datalen, u8 *out);
u32 openssl_hash_blake2s_256(u8 *data, u32 datalen, u8 *out);
u32 openssl_hash_blake2b_512(u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hash_blake2s_256(u8 *data, u32 datalen, u8 *out);
u32 libtomcrypt_hash_blake2b_512(u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hash_sha_256(u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hash_sha_512(u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hash_blake2s_256(u8 *data, u32 datalen, u8 *out);
u32 gcrypt_hash_blake2b_512(u8 *data, u32 datalen, u8 *out);
static int test_hash(test_hash_t test_hash, u8 *in, u32 inlen, u8 *out_expected);

static test_hash_t test_hashes[] = {
    {32, "libtomcrypt_hash_sha_256    ", libtomcrypt_hash_sha_256},
    {32, "openssl_hash_sha_256        ", openssl_hash_sha_256},
    {32, "gcrypt_hash_sha_256         ", gcrypt_hash_sha_256},

    {64, "libtomcrypt_hash_sha_512    ", libtomcrypt_hash_sha_512},
    {64, "openssl_hash_sha_512        ", openssl_hash_sha_512},
    {64, "gcrypt_hash_sha_512         ", gcrypt_hash_sha_512},

    {32, "libtomcrypt_hash_blake2s_256", libtomcrypt_hash_blake2s_256},
    {32, "openssl_hash_blake2s_256    ", openssl_hash_blake2s_256},
    {32, "gcrypt_hash_blake2s_256    ", gcrypt_hash_blake2s_256},

    {64, "libtomcrypt_hash_blake2b_512", libtomcrypt_hash_blake2b_512},
    {64, "openssl_hash_blake2b_512    ", openssl_hash_blake2b_512},
    {64, "gcrypt_hash_blake2b_512    ", gcrypt_hash_blake2b_512},
};

int main(int argc, char **argv)
{
    u32 datalens[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192};

    test_hash(test_hashes[0], (u8*) "abc", 3, (u8*) "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    test_hash(test_hashes[1], (u8*) "abc", 3, (u8*) "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    test_hash(test_hashes[2], (u8*) "abc", 3, (u8*) "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    printf("\n");

    test_hash(test_hashes[3], (u8*) "abc", 3, (u8*) "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    test_hash(test_hashes[4], (u8*) "abc", 3, (u8*) "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    test_hash(test_hashes[5], (u8*) "abc", 3, (u8*) "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    printf("\n");

    test_hash(test_hashes[6], (u8*) "abc", 3, (u8*) "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    test_hash(test_hashes[7], (u8*) "abc", 3, (u8*) "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    test_hash(test_hashes[8], (u8*) "abc", 3, (u8*) "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    printf("\n");

    test_hash(test_hashes[9], (u8*) "abc",  3, (u8*) "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    test_hash(test_hashes[10], (u8*) "abc", 3, (u8*) "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    test_hash(test_hashes[11], (u8*) "abc", 3, (u8*) "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");

    return 0;
}

// implementation
static int test_hash(test_hash_t test_hash, u8 *in, u32 inlen, u8 *out_expected)
{
    u8 *out;
    out = (u8*) malloc(test_hash.outlen);

    if (test_hash.hash(in, inlen, out) != test_hash.outlen) { return -1; }

    printf("%s Output: ", test_hash.name);
    for (u32 i = 0; i < test_hash.outlen; i++) { printf("%02x", out[i]); }
    printf("\n");

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
