
#include "fae.h"
#include "hash.h"
#include "hmac.h"
#include <string.h>
#include <openssl/rand.h>

static u32 openssl_encrypt(const EVP_CIPHER *cipher, EVP_CIPHER_CTX *cipher_ctx, u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out, u32 *outlen);
static u32 openssl_decrypt(const EVP_CIPHER *cipher, EVP_CIPHER_CTX *cipher_ctx, u8 *key, u8 *iv, u8 *ct, u32 ctlen, u8 *dec_in, u32 *dec_inlen);

u32 fae_kg(fae_ctx_t *fae_ctx, char *enc_algorithm, char *auth_algorithm, char *upd_algorithm)
{
    // set the key and iv length for the encryption algorithm
    fae_ctx->keylen = 32;
    fae_ctx->enc_func = openssl_encrypt;
    fae_ctx->evp_cipher_ctx = EVP_CIPHER_CTX_new();
    if (strcmp(enc_algorithm, "aes-256-ctr") == 0) {
        fae_ctx->ivlen = 16;
        fae_ctx->cipher = EVP_aes_256_ctr();
    } else if (strcmp(enc_algorithm, "aes-128-ctr") == 0) {
        fae_ctx->ivlen = 16;
        fae_ctx->cipher = EVP_aes_128_cbc();
    } else if (strcmp(enc_algorithm, "aes-256-cbc") == 0) {
        fae_ctx->ivlen = 16;
        fae_ctx->cipher = EVP_aes_256_cbc();
    } else if (strcmp(enc_algorithm, "chacha20-poly1305") == 0) {
        fae_ctx->ivlen = 16;
        fae_ctx->cipher = EVP_chacha20_poly1305();
    } else {
        return -1;
    }
    if (RAND_bytes(fae_ctx->iv, fae_ctx->ivlen) != 1) { return -1; }
    if (RAND_bytes(fae_ctx->enc_key, fae_ctx->keylen) != 1) { return -1; }
    if (RAND_bytes(fae_ctx->auth_key, fae_ctx->keylen) != 1) { return -1; }
    // set the authentication HMAC function
    if (strcmp(auth_algorithm, "hmac-sha-256") == 0) {
        fae_ctx->auth_func = openssl_hmac_sha_256;
    } else if (strcmp(auth_algorithm, "hmac-blake2s-256") == 0) {
        fae_ctx->auth_func = openssl_hmac_blake2s_256;
    } else {
        return -1;
    }
    // set the update hashing function
    if (strcmp(upd_algorithm, "sha-256") == 0) {
        fae_ctx->upd_func = openssl_hash_sha_256;
    } else if (strcmp(upd_algorithm, "blake2s-256") == 0) {
        fae_ctx->upd_func = openssl_hash_blake2s_256;
    } else {
        return -1;
    }
    fae_ctx->enc_time = fae_ctx->auth_time = fae_ctx->upd_time = fae_ctx->agg_time = 0;
    // fae_ctx->counter = 0;

    return 0;
}

u32 fae_enc(fae_ctx_t *fae_ctx, u8 *in, u32 inlen, fae_out_t *fae_out)
{
    u32 len;
    u8 tmp_data[64];
    struct timespec t0, t1;

    // encrypt the data
    clock_gettime(CLOCK_MONOTONIC, &t0);
    openssl_encrypt(fae_ctx->cipher, fae_ctx->evp_cipher_ctx, fae_ctx->enc_key, fae_ctx->iv, in, inlen, fae_out->ciphertext, &fae_out->ciphertextlen);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    fae_ctx->enc_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);

    // authenticate the encrypted data
    clock_gettime(CLOCK_MONOTONIC, &t0);
    fae_ctx->auth_func(fae_ctx->auth_key, fae_ctx->keylen, fae_out->ciphertext, fae_out->ciphertextlen, fae_out->sig);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    fae_ctx->auth_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    memcpy(tmp_data, fae_out->agg_sig, 32);
    memcpy(tmp_data + 32, fae_out->sig, 32);
    fae_ctx->upd_func(tmp_data, 64, fae_out->agg_sig);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    fae_ctx->agg_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    
    return 0;
}

u32 fae_dec(fae_ctx_t *fae_ctx, u8 *in, u32 *inlen, fae_out_t *fae_out)
{
    u32 len;
    // u8 tag[32];

    // verify the authentication tag
    // fae_ctx->auth_func(fae_ctx->key, fae_ctx->keylen, fae_out->ciphertext, fae_out->ciphertextlen, tag);
    // if (memcmp(tag, fae_out->sig, 32) != 0) { return -1; }
    // decrypt the data
    openssl_decrypt(fae_ctx->cipher, fae_ctx->evp_cipher_ctx, fae_ctx->enc_key, fae_ctx->iv, fae_out->ciphertext, fae_out->ciphertextlen, in, &len);
    
    return 0;
}

u32 fae_upd(fae_ctx_t *fae_ctx)
{
    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    fae_ctx->upd_func(fae_ctx->enc_key, fae_ctx->keylen, fae_ctx->enc_key);
    fae_ctx->upd_func(fae_ctx->auth_key, fae_ctx->keylen, fae_ctx->auth_key);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    fae_ctx->upd_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);

    return 0;
}

static u32 openssl_encrypt(const EVP_CIPHER *cipher, EVP_CIPHER_CTX *cipher_ctx, u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out, u32 *outlen)
{
    u32 len;
    // EVP_CIPHER_CTX *cipher_ctx1 = EVP_CIPHER_CTX_new();

    if (EVP_EncryptInit(cipher_ctx, cipher, key, iv) != 1) { return -1; }
    if (EVP_EncryptUpdate(cipher_ctx, out, (int*)&len, in, inlen) != 1) { return -1; }
    *outlen = len;
    if (EVP_EncryptFinal(cipher_ctx, out + len, (int*)&len) != 1) { return -1; }
    *outlen += len;

    // EVP_CIPHER_CTX_free(cipher_ctx1);
    return len;
}

static u32 openssl_decrypt(const EVP_CIPHER *cipher, EVP_CIPHER_CTX *cipher_ctx, u8 *key, u8 *iv, u8 *ct, u32 ctlen, u8 *dec_in, u32 *dec_inlen)
{
    u32 len;
    // EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();

    if (EVP_DecryptInit(cipher_ctx, cipher, key, iv) != 1) { return -1; }
    if (EVP_DecryptUpdate(cipher_ctx, dec_in, (int*)&len, ct, ctlen) != 1) { return -1; }
    *dec_inlen = len;
    if (EVP_DecryptFinal(cipher_ctx, dec_in + len, (int*)&len) != 1) { return -1; }
    *dec_inlen += len;
    
    // EVP_CIPHER_CTX_free(evp_cipher_ctx);
    return len;
}
