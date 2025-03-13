
#include <string.h>
#include "prf.h"

int prf_init(const u8 *key, const u8 *iv, const char *cipher, PRF_CTX *ctx) {
    if (!(ctx->ctx = EVP_CIPHER_CTX_new())) { return -1; }
    if (strcmp(cipher, "aes-128-ctr") == 0) {
        ctx->cipher = EVP_aes_128_ctr();
    } else if (strcmp(cipher, "chacha20") == 0) {
        ctx->cipher = EVP_chacha20();
    } else {
        return -1;
    }
    ctx->key = (u8*) key;
    ctx->iv  = (u8*) iv;
    if (EVP_EncryptInit_ex(ctx->ctx, ctx->cipher, NULL, ctx->key, ctx->iv) != 1) { return -1; }

    return 0;
}

int prf_exec(const u8 *in, u32 inlen, u8 *out, u32 *outlen, PRF_CTX *ctx) {
    int len;
    
    if (EVP_EncryptUpdate(ctx->ctx, out, &len, in, inlen) != 1) { return -1; }
    *outlen = len;
    if (EVP_EncryptFinal_ex(ctx->ctx, out + len, &len) != 1) { return -1; }
    *outlen += len;

    return 0;
}

int prf_free(PRF_CTX *ctx) {
    EVP_CIPHER_CTX_free(ctx->ctx);

    return 0;
}
