
#ifndef LC_UMAC_H
#define LC_UMAC_H

#include <gmp.h>
#include "common.h"
#include "../types.h"

struct LC_UMAC_CTX {
    mpz_t a;
    mpz_t b;
    mpz_t p;
    mpz_t in_mpz;
    mpz_t out_mpz;
    mpz_t tmp_mpz;
    u32 prime_bits;
    u32 prime_bytes;
    struct timespec t0;
    struct timespec t1;
    double cpu_time;
};

typedef struct LC_UMAC_CTX LC_UMAC_CTX;

/**
 * @brief Initialize the LC-MAC context
 * 
 * @param ctx The LC-MAC context
 * @param bitlength The bitlength of the MAC
 * @return int 0 if successful, -1 otherwise
 */
int lc_umac_init(LC_UMAC_CTX *ctx, u32 prime_bits);

/**
 * @brief Execute the LC-MAC
 * 
 * @param in The input
 * @param inlen The length of the input
 * @param out The output
 * @param outlen The length of the output
 * @param ctx The LC-MAC context
 * @return int 0 if successful, -1 otherwise
 */
int lc_umac_update(const u8 *in, const u32 inlen, LC_UMAC_CTX *ctx, double *cpu_time);

/**
 * @brief Finalize the LC-MAC
 * 
 * @param out The output
 * @param outlen The length of the output
 * @param ctx The LC-MAC context
 * @return int 0 if successful, -1 otherwise
 */
int lc_umac_final(u8 *out, u32 *outlen, LC_UMAC_CTX *ctx, double *cpu_time);

/**
 * @brief Memory version of the LC-MAC
 * 
 * @param in The input
 * @param inlen The length of the input
 * @param out The output
 * @param outlen The length of the output
 * @param ctx The LC-MAC context
 * @return int 0 if successful, -1 otherwise
 */
int lc_umac_memory(const u8 *in, const u32 inlen, u8 *out, u32 *outlen, LC_UMAC_CTX *ctx, double *cpu_time);

/**
 * @brief Free the LC-MAC context
 * 
 * @param ctx The LC-MAC context
 * @return int 0 if successful, -1 otherwise
 */
int lc_umac_free(LC_UMAC_CTX *ctx);

#endif // LC_UMAC_H