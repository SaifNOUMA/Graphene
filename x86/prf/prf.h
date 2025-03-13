
#ifndef PRF_H
#define PRF_H

#include "types.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

struct PRF_CTX {
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;
    u8 *key;
    u8 *iv;
};

typedef struct PRF_CTX PRF_CTX;

/**
 * @brief Initialize the PRF context
 * 
 * @param key The key
 * @param iv The IV
 * @param cipher The cipher
 * @param ctx The PRF context
 * @return int 0 if successful, -1 otherwise
 */
int prf_init(const u8 *key, const u8 *iv, const char *cipher, struct PRF_CTX *ctx);

/**
 * @brief Execute the PRF
 * 
 * @param in The input
 * @param inlen The length of the input
 * @param out The output
 * @param outlen The length of the output
 * @param ctx The PRF context
 * @return int 0 if successful, -1 otherwise
 */
int prf_exec(const u8 *in, u32 inlen, u8 *out, u32 *outlen, struct PRF_CTX *ctx);

/**
 * @brief Free the PRF context
 * 
 * @param ctx The PRF context
 * @return int 0 if successful, -1 otherwise
 */
int prf_free(struct PRF_CTX *ctx);

#endif // PRF_H