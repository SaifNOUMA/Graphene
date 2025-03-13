
#ifndef RNG_GMP_H
#define RNG_GMP_H

#include <gmp.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "prf.h"

struct RNG_GMP_CTX {
    mpz_t p;
    u8 *input;
    u32 bitlength;
    u32 bytelength;
    PRF_CTX prf_ctx;
    gmp_randstate_t gmp_state;
};

typedef struct RNG_GMP_CTX RNG_GMP_CTX;

/**
 * @brief Initialize the RNG context
 * 
 * @param method The method used for generation
 * @param prf_ctx The PRF context
 * @param ctx The RNG context
 * @return int 0 if successful, -1 otherwise
 */
int rng_gmp_init(const char *method, u32 bitlength, mpz_t p, struct RNG_GMP_CTX *ctx);

/**
 * @brief Generate a random number
 * 
 * @param a The generated number
 * @param bitlength The bit length of the number
 * @param method The method used for generation
 * @param prf_ctx The PRF context
 * @return int 0 if successful, -1 otherwise
 */
int rng_gmp_exec(mpz_t a, struct RNG_GMP_CTX rng_ctx);

/**
 * @brief Free the RNG context
 * 
 * @param ctx The RNG context
 * @return int 0 if successful, -1 otherwise
 */
int rng_gmp_clear(struct RNG_GMP_CTX *ctx);

#endif // RNG_GMP_H