
#ifndef RNG_GMP_H
#define RNG_GMP_H

#include <time.h>
#include <stdio.h>
#include <string.h>
#include "prf.h"

struct RNG_BYTE_CTX {
    u8 *input;
    u32 maxdatalen;
    PRF_CTX prf_ctx;
};

typedef struct RNG_BYTE_CTX RNG_BYTE_CTX;

/**
 * @brief Initialize the RNG context
 * 
 * @param method The method used for generation
 * @param datalen The length of the data
 * @param ctx The RNG context
 * @return int 0 if successful, -1 otherwise
 */
int rng_byte_init(const char *method, u32 datalen, RNG_BYTE_CTX *ctx);

/**
 * @brief Generate a random number
 * 
 * @param data The generated number
 * @param rng_ctx The RNG context
 * @return int 0 if successful, -1 otherwise
 */
int rng_byte_exec(u8 *data, u32 datalen, RNG_BYTE_CTX rng_ctx);

/**
 * @brief Free the RNG context
 * 
 * @param ctx The RNG context
 * @return int 0 if successful, -1 otherwise
 */
int rng_byte_clear(RNG_BYTE_CTX *ctx);

#endif // RNG_GMP_H