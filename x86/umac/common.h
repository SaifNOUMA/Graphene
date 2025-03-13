
#ifndef COMMON_H
#define COMMON_H

#include <gmp.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "../prf/prf.h"
#define BYTE_LEN 8
#define OFFLNE_MODE 0
#define NORMAL_MODE 1
#define DEBUG
#define DATA_TRANSFER
 #define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

struct RNG_CTX {
    u8 *input;
    u32 bitlength;
    u32 bytelength;
    const char *method;
    struct PRF_CTX prf_ctx;
    gmp_randstate_t gmp_state;
    mpz_t p;
};

/**
 * @brief Initialize the RNG context
 * 
 * @param method The method used for generation
 * @param prf_ctx The PRF context
 * @param ctx The RNG context
 * @return int 0 if successful, -1 otherwise
 */
int rng_init(const char *method, u32 bitlength, mpz_t p, struct RNG_CTX *ctx);

/**
 * @brief Generate a prime number
 * 
 * @param prime The prime number
 * @param bit_length The bit length of the prime number
 */
int rng_prime(mpz_t prime, unsigned int bit_length);

/**
 * @brief Generate a random number
 * 
 * @param a The generated number
 * @param bitlength The bit length of the number
 * @param method The method used for generation
 * @param prf_ctx The PRF context
 * @return int 0 if successful, -1 otherwise
 */
int rng_mpz(mpz_t a, struct RNG_CTX rng_ctx);

/**
 * @brief Free the RNG context
 * 
 * @param ctx The RNG context
 * @return int 0 if successful, -1 otherwise
 */
int rng_clear(struct RNG_CTX *ctx);

/**
 * @brief Save an array to a CSV file
 * 
 * @param filename The filename
 * @param rows The number of rows
 * @param cols The number of columns
 * @param array The array
 */
void save_to_csv(const char *filename, u32 rows, u32 cols, double array[128][128]);

#endif // COMMON_H