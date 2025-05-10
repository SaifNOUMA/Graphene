
#include "rng.h"

int rng_init(const char *method, u32 bitlength, mpz_t p, struct RNG_CTX *ctx)
{
    if (strcmp(method, "aes-128-ctr") == 0)
    {
        u8 key[16], iv[16];
        if (RAND_bytes(key, 16) != 1 || RAND_bytes(iv, 16) != 1) { return -1; }
        prf_init(key, iv, method, &ctx->prf_ctx);
    } else if (strcmp(method, "chacha20") == 0) {
        u8 key[32], iv[12];
        if (RAND_bytes(key, 32) != 1 || RAND_bytes(iv, 12) != 1) { return -1; }
        prf_init(key, iv, method, &ctx->prf_ctx);
    } else {
        printf("ERROR: Invalid RNG method\n");
        return -1;
    }
    mpz_set(ctx->p, p);
    ctx->method = method;
    ctx->bitlength = bitlength;
    ctx->bytelength = (bitlength+7)/BYTE_LEN;
    ctx->input = (u8*)malloc((bitlength+7)/BYTE_LEN);
    memset(ctx->input, 0, (bitlength+7)/BYTE_LEN);

    return 0;
}

int rng_prime(mpz_t prime, unsigned int bit_length) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    mpz_rrandomb(prime, state, bit_length);
    mpz_nextprime(prime, prime);
    gmp_randclear(state);

    return 0;
}

int rng_mpz(mpz_t a, struct RNG_CTX rng_ctx)
{
    u32     outlen;
    size_t _outlen;
    u8  out[rng_ctx.bytelength];
    if (prf_exec(rng_ctx.input, rng_ctx.bytelength, out, &outlen, &rng_ctx.prf_ctx) != 0) { return -1; }
    _outlen = (size_t)outlen;
    mpz_import(a, _outlen, 1, sizeof(u8), 0, 0, out);
    mpz_mod(a, a, rng_ctx.p);

    return 0;
}

int rng_clear(struct RNG_CTX *ctx)
{
    prf_free(&ctx->prf_ctx);
    free(ctx->input);

    return 0;
}
