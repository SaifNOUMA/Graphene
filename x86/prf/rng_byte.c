
#include "rng_byte.h"

int rng_byte_init(const char *method, u32 maxdatalen, RNG_BYTE_CTX *rng_byte_ctx)
{
    u8 key[32], iv[16];
    if (strcmp(method, "aes-128-ctr") == 0)
    {
        if (RAND_bytes(key, 16) != 1 || RAND_bytes(iv, 16) != 1) { return -1; }
    } else if (strcmp(method, "chacha20") == 0) {
        if (RAND_bytes(key, 32) != 1 || RAND_bytes(iv, 12) != 1) { return -1; }
    } else {
        printf("ERROR: Invalid RNG method\n");
        return -1;
    }
    if (prf_init(key, iv, method, &rng_byte_ctx->prf_ctx) != 0) { return -1; }
    rng_byte_ctx->maxdatalen = maxdatalen;
    rng_byte_ctx->input = (u8*)malloc(rng_byte_ctx->maxdatalen);
    memset(rng_byte_ctx->input, 0, rng_byte_ctx->maxdatalen);

    return 0;
}

int rng_byte_exec(u8 *data, u32 datalen, RNG_BYTE_CTX rng_ctx)
{
    u32 outlen;

    if (prf_exec(rng_ctx.input, datalen, data, &outlen, &rng_ctx.prf_ctx) != 0) { return -1; }

    return 0;
}

int rng_byte_clear(RNG_BYTE_CTX *ctx)
{
    free(ctx->input);
    if (prf_free(&ctx->prf_ctx) != 0) { return -1; }

    return 0;
}
