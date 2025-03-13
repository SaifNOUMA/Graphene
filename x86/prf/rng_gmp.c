
#include "rng_gmp.h"

int rng_gmp_init(const char *method, u32 bitlength, mpz_t p, RNG_GMP_CTX *ctx)
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
    if (prf_init(key, iv, method, &ctx->prf_ctx) != 0) { return -1; }
    mpz_set(ctx->p, p);
    ctx->bitlength = bitlength;
    ctx->bytelength = (bitlength+7)/8;
    ctx->input = (u8*)malloc(ctx->bytelength);
    memset(ctx->input, 0, ctx->bytelength);

    return 0;
}

int rng_gmp_exec(mpz_t a, RNG_GMP_CTX rng_ctx)
{
    u32 outlen;
    size_t _outlen;
    u8  out[rng_ctx.bytelength];
    if (prf_exec(rng_ctx.input, rng_ctx.bytelength, out, &outlen, &rng_ctx.prf_ctx) != 0) { return -1; }
    _outlen = (size_t)outlen;
    mpz_import(a, _outlen, 1, sizeof(u8), 0, 0, out);
    mpz_mod(a, a, rng_ctx.p);

    return 0;
}

int rng_gmp_clear(RNG_GMP_CTX *ctx)
{
    free(ctx->input);
    prf_free(&ctx->prf_ctx);

    return 0;
}
