
#ifndef SQ_UMAC_H
#define SQ_UMAC_H

#include "common.h"

struct SQ_UMAC_CTX {
    mpz_t a;
    mpz_t p;
    mpz_t in_mpz;
    mpz_t out_mpz;
    mpz_t tmp_mpz;
    mpz_t mask;
    u32 prime_bits;
    u32 prime_bytes;
    struct timespec t0;
    struct timespec t1;
    double cpu_time;
};

typedef struct SQ_UMAC_CTX SQ_UMAC_CTX;

/**
 * @brief Initialize the SQ-MAC context
 * 
 * @param ctx The SQ-MAC context
 * @param bitlength The bitlength of the MAC
 * @return int 0 if successful, -1 otherwise
 */
int sq_umac_init(struct SQ_UMAC_CTX *ctx, u32 prime_bits);

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
int sq_umac_update(const u8 *in, const u32 inlen, SQ_UMAC_CTX *ctx, double *cpu_t);

/**
 * @brief Finalize the LC-MAC
 * 
 * @param out The output
 * @param outlen The length of the output
 * @param ctx The LC-MAC context
 * @return int 0 if successful, -1 otherwise
 */
int sq_umac_final(u8 *out, u32 *outlen, SQ_UMAC_CTX *ctx, double *cpu_t);

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
int sq_umac_memory(const u8 *in, const u32 inlen, u8 *out, u32 *outlen, SQ_UMAC_CTX *ctx, double *cpu_time);

/**
 * @brief Free the SQ-MAC context
 * 
 * @param ctx The SQ-MAC context
 * @return int 0 if successful, -1 otherwise
 */
int sq_umac_free(struct SQ_UMAC_CTX *ctx);

#endif // SQ_uMAC_H