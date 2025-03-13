
#include "hash.h"

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
