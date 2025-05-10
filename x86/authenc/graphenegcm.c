
#include <time.h>
#include "common.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

struct graphene_ctx {
    EVP_CIPHER_CTX *evp_cipher_ctx;
    const EVP_CIPHER *cipher;
    u8 iv[16];
    u8 enc_key[32];
    u32 keylen;
    u32 ivlen;
};

struct graphene_out {
    u8 ciphertext[32];
    u32 ciphertextlen;
    u8 sig[32];
    u8 agg_sig[32];
    u32 siglen;
};

typedef struct graphene_ctx graphene_ctx_t;
typedef struct graphene_out graphene_out_t;

u32 graphenegcm_enc(struct graphene_ctx *ctx, u8 *in, u32 inlen, u8 *out, u32 *outlen);
u32 graphenegcm_dec(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *dec_in, u32 *dec_inlen);
u32 graphenegcm_auth(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen);
u32 graphenegcm_ver(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen);
u32 graphenegcm_keyupd(const uint8_t *old_key, uint8_t *new_key);
u32 graphenegcm_agg(const uint8_t *accumulator, const uint8_t *input, uint8_t *output);
u32 graphenegcm_free(struct graphene_ctx *ctx);

u32 graphenegcm_kg(struct graphene_ctx *ctx);
u32 graphenegcm_authenc(struct graphene_ctx *ctx, u8 *in, u32 inlen, struct graphene_out *out);
u32 graphenegcm_verdec(struct graphene_ctx *ctx, struct graphene_out *out, u8 *dec_in, u32 *dec_inlen);

int main() {
    struct graphene_ctx ctx;
    struct graphene_out out;
    u8 in[32] = {0};
    u32 inlen = 32;
    u32 dec_inlen;

    if (graphenegcm_kg(&ctx) != 0) {
        printf("Key generation failed\n");
        return -1;
    }

    if (graphenegcm_authenc(&ctx, in, inlen, &out) != 0) {
        printf("Authenc failed\n");
        return -1;
    }

    if (graphenegcm_verdec(&ctx, &out, in, &dec_inlen) != 0) {
        printf("Verdec failed\n");
        return -1;
    }

    graphenegcm_free(&ctx);
    return 0;
}

u32 graphenegcm_kg(struct graphene_ctx *ctx)
{
    ctx->ivlen = 16;
    ctx->keylen = 32;
    ctx->cipher = EVP_aes_128_gcm();
    ctx->evp_cipher_ctx = EVP_CIPHER_CTX_new();

    if (RAND_bytes(ctx->iv, ctx->ivlen) != 1) { return -1; }
    if (RAND_bytes(ctx->enc_key, ctx->keylen) != 1) { return -1; }

    return 0;
}

u32 graphenegcm_authenc(struct graphene_ctx *ctx, u8 *in, u32 inlen, struct graphene_out *out)
{
    u32 outlen = 0;
    if (graphenegcm_enc(ctx, in, inlen, out->ciphertext, &outlen) != 0) { return -1; }
    out->ciphertextlen = outlen;

    if (graphenegcm_agg(out->agg_sig, out->sig, out->agg_sig) != 0) { return -1; }

    // key update
    if (graphenegcm_keyupd(ctx->enc_key, ctx->enc_key) != 0) { return -1; }

    return 0;
}

u32 graphenegcm_verdec(struct graphene_ctx *ctx, struct graphene_out *out, u8 *dec_in, u32 *dec_inlen)
{
    u32 ctlen = out->ciphertextlen;
    u8 *ct = out->ciphertext;
    
    if (graphenegcm_dec(ctx, ct, ctlen, dec_in, dec_inlen) != 0) { return -1; }
    
    return 0;
}

u32 graphenegcm_enc(struct graphene_ctx *ctx, u8 *in, u32 inlen, u8 *out, u32 *outlen)
{
    u32 len;
    if (EVP_EncryptInit(ctx->evp_cipher_ctx, ctx->cipher, ctx->enc_key, ctx->iv) != 1) { return -1; }
    if (EVP_EncryptUpdate(ctx->evp_cipher_ctx, out, (int*)&len, in, inlen) != 1) { return -1; }
    *outlen = len;
    if (EVP_EncryptFinal(ctx->evp_cipher_ctx, out + len, (int*)&len) != 1) { return -1; }
    *outlen += len;

    return 0;
}

u32 graphenegcm_dec(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *dec_in, u32 *dec_inlen)
{
    u32 len;
    if (EVP_DecryptInit(ctx->evp_cipher_ctx, ctx->cipher, ctx->enc_key, ctx->iv) != 1) { return -1; }
    if (EVP_DecryptUpdate(ctx->evp_cipher_ctx, dec_in, (int*)&len, ct, ctlen) != 1) { return -1; }
    *dec_inlen = len;
    if (EVP_DecryptFinal(ctx->evp_cipher_ctx, dec_in + len, (int*)&len) != 1) { return -1; }
    *dec_inlen += len;

    return 0;
}

u32 graphenegcm_keyupd(const uint8_t *old_key, uint8_t *new_key)
{
    SHA256(old_key, 16, new_key);
    return 0;
}

u32 graphenegcm_agg(const uint8_t *accumulator, const uint8_t *input, uint8_t *output)
{
    uint8_t concat[32];
    memcpy(concat, accumulator, 16);
    memcpy(concat + 16, input, 16);

    SHA256(concat, 32, output);

    return 0;
}

u32 graphenegcm_free(struct graphene_ctx *ctx)
{
    EVP_CIPHER_CTX_free(ctx->evp_cipher_ctx);
    return 0;
}
