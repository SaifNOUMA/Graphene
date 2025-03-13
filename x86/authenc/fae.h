
#ifndef _FAE_H_
#define _FAE_H_

#include "../types.h"
#include <openssl/evp.h>
#define MAX_IV_LEN 1024
#define MAX_KEY_LEN 1024
#define MAX_SIG_LEN 1024
#define MAX_CIPHERTEXT_LEN 40000

typedef struct {
    u32 ivlen;
    u32 keylen;
    u8  iv[MAX_IV_LEN];
    u8  enc_key[MAX_KEY_LEN];
    u8  auth_key[MAX_KEY_LEN];
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *evp_cipher_ctx;
    u32 (*upd_func)  (u8*, u32, u8*);
    u32 (*enc_func)  (const EVP_CIPHER*, EVP_CIPHER_CTX*, u8*, u8*, u8*, u32, u8*, u32*);
    u32 (*auth_func) (u8*, u32, u8*, u32, u8*);
    double enc_time;
    double auth_time;
    double agg_time;
    double upd_time;
    u32 counter;
    // double dec_time;
} fae_ctx_t;

typedef struct {
    u32 siglen;
    u32 ciphertextlen;
    u8  sig[MAX_SIG_LEN];
    u8  ciphertext[MAX_CIPHERTEXT_LEN];
    u8  agg_sig[MAX_SIG_LEN];
} fae_out_t;

/**
 * @brief Key generation for symmetric authenticated encryption
 * 
 * @param fae_ctx The symmetric authenticated encryption context
 * @param enc_algorithm The encryption algorithm
 * @param auth_algorithm The authentication algorithm
 * @param upd_algorithm The update algorithm
 * @return u32 0 if successful, -1 otherwise
 */
u32 fae_kg(fae_ctx_t *fae_ctx, char *enc_algorithm, char *auth_algorithm, char *upd_algorithm);

/**
 * @brief Update the symmetric authenticated encryption context
 * 
 * @param fae_ctx The symmetric authenticated encryption context
 * @return u32 0 if successful, -1 otherwise
 */
u32 fae_upd(fae_ctx_t *fae_ctx);

/**
 * @brief Symmetric authenticated encryption
 * 
 * @param fae_ctx The symmetric authenticated encryption context
 * @param in The input
 * @param inlen The length of the input
 * @param fae_out The output
 * @return u32 0 if successful, -1 otherwise
 */
u32 fae_enc(fae_ctx_t *fae_ctx, u8 *in, u32 inlen, fae_out_t *fae_out);

/**
 * @brief Symmetric decryption and authentication
 * 
 * @param fae_ctx The symmetric authenticated encryption context
 * @param in The input
 * @param inlen The length of the input
 * @param fae_out The output
 * @return u32 0 if successful, -1 otherwise
 */
u32 fae_dec(fae_ctx_t *fae_ctx, u8 *in, u32 *inlen, fae_out_t *fae_out);

#endif