
#include "hmac.h"
#include <openssl/hmac.h>

u32 openssl_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen = 0;

    if (HMAC(EVP_blake2s256(), key, keylen, data, datalen, out, &outlen) == NULL) { return -1; }

    return outlen;
}

u32 openssl_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen;

    if (HMAC(EVP_sha256(), key, keylen, data, datalen, out, &outlen) == NULL) { return -1; }

    return outlen;
}
