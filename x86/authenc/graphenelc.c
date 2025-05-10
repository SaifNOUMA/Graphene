
#include <time.h>
#include "common.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <gmp.h>
#include "lc_umac.h"

struct graphene_ctx {
    EVP_CIPHER_CTX *evp_cipher_ctx;
    const EVP_CIPHER *cipher;
    LC_UMAC_CTX umac_ctx;
    u8 *umac_key;
    u32 prime_bits;
    u8 iv[16];
    u8 enc_key[32];
    u8 auth_key[32];
    u32 keylen;
    u32 ivlen;
};

struct graphene_out {
    u8 ciphertext[32];
    u8 sig[32];
    u8 agg_sig[32];
    u32 siglen;
    u32 ciphertextlen;
};

typedef struct graphene_ctx graphene_ctx_t;
typedef struct graphene_out graphene_out_t;

u32 graphenelc_enc(struct graphene_ctx *ctx, u8 *in, u32 inlen, u8 *out, u32 *outlen);
u32 graphenelc_dec(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *dec_in, u32 *dec_inlen);
u32 graphenelc_auth(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen);
u32 graphenelc_ver(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen);
u32 graphenelc_keyupd(const uint8_t *old_key, uint8_t *new_key);
u32 graphenelc_agg(const uint8_t *accumulator, const uint8_t *input, uint8_t *output);
u32 graphenelc_free(struct graphene_ctx *ctx);


u32 graphenelc_kg(struct graphene_ctx *ctx);
u32 graphenelc_authenc(struct graphene_ctx *ctx, u8 *in, u32 inlen, struct graphene_out *out);
u32 graphenelc_verdec(struct graphene_ctx *ctx, struct graphene_out *out, u8 *dec_in, u32 *dec_inlen);

int main() {
    struct graphene_ctx ctx;
    struct graphene_out out;
    u8 in[32] = {0};
    u32 inlen = 32;
    u32 dec_inlen;

    if (graphenelc_kg(&ctx) != 0) {
        printf("Key generation failed\n");
        return -1;
    }

    if (graphenelc_authenc(&ctx, in, inlen, &out) != 0) {
        printf("Authenc failed\n");
        return -1;
    }

    if (graphenelc_verdec(&ctx, &out, in, &dec_inlen) != 0) {
        printf("Verdec failed\n");
        return -1;
    }

    return 0;
}

u32 graphenelc_kg(struct graphene_ctx *ctx)
{
    ctx->ivlen = 16;
    ctx->keylen = 32;
    ctx->cipher = EVP_aes_128_ctr();
    ctx->prime_bits = 128;
    ctx->evp_cipher_ctx = EVP_CIPHER_CTX_new();

    if (RAND_bytes(ctx->iv, ctx->ivlen) != 1) { return -1; }
    if (RAND_bytes(ctx->enc_key, ctx->keylen) != 1) { return -1; }
    if (lc_umac_init(&ctx->umac_ctx, ctx->prime_bits) != 0) { return -1; }

    return 0;
}

u32 graphenelc_authenc(struct graphene_ctx *ctx, u8 *in, u32 inlen, struct graphene_out *out)
{
    u32 outlen = 0;
    if (graphenelc_enc(ctx, in, inlen, out->ciphertext, &outlen) != 0) { return -1; }
    out->ciphertextlen = outlen;

    if (graphenelc_auth(ctx, out->ciphertext, out->ciphertextlen, out->sig, &out->siglen) != 0) { return -1; }
    if (graphenelc_agg(out->agg_sig, out->sig, out->agg_sig) != 0) { return -1; }

    // key update
    if (graphenelc_keyupd(ctx->enc_key, ctx->enc_key) != 0) { return -1; }
    if (graphenelc_keyupd(ctx->auth_key, ctx->auth_key) != 0) { return -1; }

    return 0;
}

u32 graphenelc_verdec(struct graphene_ctx *ctx, struct graphene_out *out, u8 *dec_in, u32 *dec_inlen)
{
    u32 ctlen = out->ciphertextlen;
    u8 *ct = out->ciphertext;
    
    if (graphenelc_ver(ctx, ct, ctlen, out->sig, &out->siglen) != 0) { return -1; }
    if (graphenelc_dec(ctx, ct, ctlen, dec_in, dec_inlen) != 0) { return -1; }
    
    return 0;
}

u32 graphenelc_enc(struct graphene_ctx *ctx, u8 *in, u32 inlen, u8 *out, u32 *outlen)
{
    u32 len;
    if (EVP_EncryptInit(ctx->evp_cipher_ctx, ctx->cipher, ctx->enc_key, ctx->iv) != 1) { return -1; }
    if (EVP_EncryptUpdate(ctx->evp_cipher_ctx, out, (int*)&len, in, inlen) != 1) { return -1; }
    *outlen = len;
    if (EVP_EncryptFinal(ctx->evp_cipher_ctx, out + len, (int*)&len) != 1) { return -1; }
    *outlen += len;

    return 0;
}

u32 graphenelc_dec(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *dec_in, u32 *dec_inlen)
{
    u32 len;
    if (EVP_DecryptInit(ctx->evp_cipher_ctx, ctx->cipher, ctx->enc_key, ctx->iv) != 1) { return -1; }
    if (EVP_DecryptUpdate(ctx->evp_cipher_ctx, dec_in, (int*)&len, ct, ctlen) != 1) { return -1; }
    *dec_inlen = len;
    if (EVP_DecryptFinal(ctx->evp_cipher_ctx, dec_in + len, (int*)&len) != 1) { return -1; }
    *dec_inlen += len;

    return 0;
}

u32 graphenelc_auth(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen)
{
    if (lc_umac_memory(ct, ctlen, tag, taglen, &ctx->umac_ctx, NULL) != 0) { return -1; }

    return 0;
}

u32 graphenelc_ver(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen)
{
    u8 tmp_tag[32];
    u32 tmp_taglen = 0;
    if (lc_umac_memory(ct, ctlen, tmp_tag, &tmp_taglen, &ctx->umac_ctx, NULL) != 0) { return -1; }
    if (memcmp(tmp_tag, tag, 32) != 0) { return -1; }

    return 0;
}

u32 graphenelc_keyupd(const uint8_t *old_key, uint8_t *new_key)
{
    SHA256(old_key, 16, new_key);
    return 0;
}

u32 graphenelc_agg(const uint8_t *accumulator, const uint8_t *input, uint8_t *output)
{
    // Initialize GMP integers
    mpz_t acc, inp, out;
    mpz_init(acc);
    mpz_init(inp);
    mpz_init(out);

    // Load accumulator and input into GMP integers
    mpz_import(acc, 16, 1, 1, 0, 0, accumulator);
    mpz_import(inp, 16, 1, 1, 0, 0, input);

    // Perform modular addition (mod 2^128)
    mpz_add(out, acc, inp);
    mpz_mod_2exp(out, out, 128);

    // Export the result back to the output buffer
    size_t count;
    mpz_export(output, &count, 1, 1, 0, 0, out);

    // Clear GMP integers
    mpz_clear(acc);
    mpz_clear(inp);
    mpz_clear(out); return 0;

    return 0;
}

u32 graphenelc_free(struct graphene_ctx *ctx)
{
    EVP_CIPHER_CTX_free(ctx->evp_cipher_ctx);
    lc_umac_free(&ctx->umac_ctx);
    return 0;
}
