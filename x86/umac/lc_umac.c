
#include "lc_umac.h"

int lc_umac_init(struct LC_UMAC_CTX *ctx, u32 prime_bits) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_init(ctx->a);
    mpz_init(ctx->b);
    mpz_init(ctx->p);
    mpz_init(ctx->in_mpz);
    mpz_init(ctx->out_mpz);
    mpz_init(ctx->tmp_mpz);

    ctx->prime_bits = prime_bits;
    ctx->prime_bytes = (prime_bits+7)/8;
    rng_prime(ctx->p, prime_bits);
    mpz_set_ui(ctx->out_mpz, 0);
    mpz_urandomb(ctx->a, state, prime_bits);
    mpz_urandomb(ctx->b, state, prime_bits);
    mpz_urandomb(ctx->in_mpz, state, prime_bits);
    mpz_mod(ctx->a, ctx->a, ctx->p);
    mpz_mod(ctx->b, ctx->b, ctx->p);
    gmp_randclear(state);
    return 0;
}

int lc_umac_update(const u8 *in, const u32 inlen, struct LC_UMAC_CTX *ctx, double *cpu_time) {
#ifdef DATA_TRANSFER
    size_t _inlen = (size_t)inlen;
    mpz_import(ctx->in_mpz, _inlen, 1, 1, 0, 0, in);
#endif

    clock_gettime(CLOCK_MONOTONIC, &ctx->t0);

    mpz_mul(ctx->tmp_mpz, ctx->a, ctx->in_mpz);
    mpz_add(ctx->out_mpz, ctx->out_mpz, ctx->tmp_mpz);

    clock_gettime(CLOCK_MONOTONIC, &ctx->t1);
    ctx->cpu_time = (ctx->t1.tv_sec - ctx->t0.tv_sec) * 1e9 + (ctx->t1.tv_nsec - ctx->t0.tv_nsec);
    *cpu_time += ctx->cpu_time;

    return 0;
}

int lc_umac_final(u8 *out, u32 *outlen, struct LC_UMAC_CTX *ctx, double *cpu_time) {
    
    clock_gettime(CLOCK_MONOTONIC, &ctx->t0);

    mpz_add(ctx->out_mpz, ctx->out_mpz, ctx->b);
    mpz_mod(ctx->out_mpz, ctx->out_mpz, ctx->p);

    clock_gettime(CLOCK_MONOTONIC, &ctx->t1);
    ctx->cpu_time = (ctx->t1.tv_sec - ctx->t0.tv_sec) * 1e9 + (ctx->t1.tv_nsec - ctx->t0.tv_nsec);
    *cpu_time += ctx->cpu_time;

#ifdef DATA_TRANSFER
    size_t _outlen;
    mpz_export(out, &_outlen, 1, 1, 0, 0, ctx->out_mpz);
    *outlen = (u32)_outlen;
#endif

    return 0;
}

int lc_umac_memory(const u8 *in, const u32 inlen, u8 *out, u32 *outlen, struct LC_UMAC_CTX *ctx, double *cpu_time)
{
    u32 blocks = (inlen + ctx->prime_bytes - 1) / ctx->prime_bytes;

    for (u32 block = 0; block < blocks-1; block++) {
        if (lc_umac_update(in+block*ctx->prime_bytes, ctx->prime_bytes, ctx, cpu_time) != 0) { return -1; }
    }
    if (lc_umac_update(in+(blocks-1)*ctx->prime_bytes, inlen-(blocks-1)*ctx->prime_bytes, ctx, cpu_time) != 0) { return -1; }
    if (lc_umac_final(out, outlen, ctx, cpu_time) != 0) { return -1; }

    return 0;
}

int lc_umac_free(struct LC_UMAC_CTX *ctx)
{
    mpz_clear(ctx->a);
    mpz_clear(ctx->b);
    mpz_clear(ctx->p);
    mpz_clear(ctx->in_mpz);
    mpz_clear(ctx->out_mpz);
    mpz_clear(ctx->tmp_mpz);

    return 0;
}
