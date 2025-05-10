
#include <time.h>
#include "common.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

struct graphene_ctx {
    EVP_CIPHER_CTX *evp_cipher_ctx;
    const EVP_CIPHER *cipher;
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

u32 graphenepoly_enc(struct graphene_ctx *ctx, u8 *in, u32 inlen, u8 *out, u32 *outlen);
u32 graphenepoly_dec(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *dec_in, u32 *dec_inlen);
u32 graphenepoly_auth(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen);
u32 graphenepoly_ver(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen);
u32 graphenepoly_keyupd(const uint8_t *old_key, uint8_t *new_key);
u32 graphenepoly_agg(const uint8_t *accumulator, const uint8_t *input, uint8_t *output);
u32 graphenepoly_free(struct graphene_ctx *ctx);

u32 graphenepoly_kg(struct graphene_ctx *ctx);
u32 graphenepoly_authenc(struct graphene_ctx *ctx, u8 *in, u32 inlen, struct graphene_out *out);
u32 graphenepoly_verdec(struct graphene_ctx *ctx, struct graphene_out *out, u8 *dec_in, u32 *dec_inlen);

int main() {
    struct graphene_ctx ctx;
    struct graphene_out out;
    u8 in[32] = {0};
    u32 inlen = 32;
    u32 dec_inlen;

    if (graphenepoly_kg(&ctx) != 0) {
        printf("Key generation failed\n");
        return -1;
    }

    if (graphenepoly_authenc(&ctx, in, inlen, &out) != 0) {
        printf("Authenc failed\n");
        return -1;
    }

    if (graphenepoly_verdec(&ctx, &out, in, &dec_inlen) != 0) {
        printf("Verdec failed\n");
        return -1;
    }

    printf("Success\n");
    return 0;
}

u32 graphenepoly_kg(struct graphene_ctx *ctx)
{
    ctx->ivlen = 16;
    ctx->keylen = 32;
    ctx->cipher = EVP_aes_128_ctr();
    ctx->evp_cipher_ctx = EVP_CIPHER_CTX_new();

    if (RAND_bytes(ctx->iv, ctx->ivlen) != 1) { return -1; }
    if (RAND_bytes(ctx->enc_key, ctx->keylen) != 1) { return -1; }
    if (RAND_bytes(ctx->auth_key, ctx->keylen) != 1) { return -1; }

    return 0;
}

u32 graphenepoly_authenc(struct graphene_ctx *ctx, u8 *in, u32 inlen, struct graphene_out *out)
{
    u32 outlen = 0;
    if (graphenepoly_enc(ctx, in, inlen, out->ciphertext, &outlen) != 0) { return -1; }
    out->ciphertextlen = outlen;

    if (graphenepoly_auth(ctx, out->ciphertext, out->ciphertextlen, out->sig, &out->siglen) != 0) { return -1; }
    if (graphenepoly_agg(out->agg_sig, out->sig, out->agg_sig) != 0) { return -1; }

    // key update
    if (graphenepoly_keyupd(ctx->enc_key, ctx->enc_key) != 0) { return -1; }
    if (graphenepoly_keyupd(ctx->auth_key, ctx->auth_key) != 0) { return -1; }

    return 0;
}

u32 graphenepoly_verdec(struct graphene_ctx *ctx, struct graphene_out *out, u8 *dec_in, u32 *dec_inlen)
{
    u32 ctlen = out->ciphertextlen;
    u8 *ct = out->ciphertext;
    
    if (graphenepoly_ver(ctx, ct, ctlen, out->sig, &out->siglen) != 0) { return -1; }
    if (graphenepoly_dec(ctx, ct, ctlen, dec_in, dec_inlen) != 0) { return -1; }
    
    return 0;
}

u32 graphenepoly_enc(struct graphene_ctx *ctx, u8 *in, u32 inlen, u8 *out, u32 *outlen)
{
    u32 len;
    if (EVP_EncryptInit(ctx->evp_cipher_ctx, ctx->cipher, ctx->enc_key, ctx->iv) != 1) { return -1; }
    if (EVP_EncryptUpdate(ctx->evp_cipher_ctx, out, (int*)&len, in, inlen) != 1) { return -1; }
    *outlen = len;
    if (EVP_EncryptFinal(ctx->evp_cipher_ctx, out + len, (int*)&len) != 1) { return -1; }
    *outlen += len;

    return 0;
}

u32 graphenepoly_dec(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *dec_in, u32 *dec_inlen)
{
    u32 len;
    if (EVP_DecryptInit(ctx->evp_cipher_ctx, ctx->cipher, ctx->enc_key, ctx->iv) != 1) { return -1; }
    if (EVP_DecryptUpdate(ctx->evp_cipher_ctx, dec_in, (int*)&len, ct, ctlen) != 1) { return -1; }
    *dec_inlen = len;
    if (EVP_DecryptFinal(ctx->evp_cipher_ctx, dec_in + len, (int*)&len) != 1) { return -1; }
    *dec_inlen += len;

    return 0;
}

u32 graphenepoly_auth(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen)
{
    EVP_MAC_CTX *poly_mac_ctx;
    EVP_MAC *poly_mac;
    poly_mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if (poly_mac == NULL) { return -1; }
    poly_mac_ctx = EVP_MAC_CTX_new(poly_mac);
    if (poly_mac_ctx == NULL) { return -1; }

    if (EVP_MAC_init(poly_mac_ctx, ctx->auth_key, ctx->keylen, NULL) != 1) { return -1; }
    if (EVP_MAC_update(poly_mac_ctx, ct, ctlen) != 1) { return -1; }
    if (EVP_MAC_final(poly_mac_ctx, tag, (size_t*)taglen, 16) != 1) { return -1; }

    EVP_MAC_free(poly_mac);
    EVP_MAC_CTX_free(poly_mac_ctx);

    return 0;
}

u32 graphenepoly_ver(struct graphene_ctx *ctx, u8 *ct, u32 ctlen, u8 *tag, u32 *taglen)
{
    EVP_MAC_CTX *poly_mac_ctx;
    EVP_MAC *poly_mac;
    poly_mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if (poly_mac == NULL) { return -1; }
    poly_mac_ctx = EVP_MAC_CTX_new(poly_mac);
    if (poly_mac_ctx == NULL) { return -1; }

    if (EVP_MAC_init(poly_mac_ctx, ctx->auth_key, ctx->keylen, NULL) != 1) { return -1; }
    if (EVP_MAC_update(poly_mac_ctx, ct, ctlen) != 1) { return -1; }
    if (EVP_MAC_final(poly_mac_ctx, tag, (size_t*)taglen, 16) != 1) { return -1; }

    EVP_MAC_free(poly_mac);
    EVP_MAC_CTX_free(poly_mac_ctx);

    return 0;
}

u32 graphenepoly_keyupd(const uint8_t *old_key, uint8_t *new_key)
{
    SHA256(old_key, 16, new_key);
    return 0;
}

u32 graphenepoly_agg(const uint8_t *accumulator, const uint8_t *input, uint8_t *output)
{
    uint8_t concat[32];
    memcpy(concat, accumulator, 16);
    memcpy(concat + 16, input, 16);
    SHA256(concat, 32, output);
    return 0;
}

u32 graphenepoly_free(struct graphene_ctx *ctx)
{
    EVP_CIPHER_CTX_free(ctx->evp_cipher_ctx);
    return 0;
}
