
#ifndef _HASH_H_
#define _HASH_H_

#include "../types.h"
#include <openssl/evp.h>

/**
 * @brief Hashes the data using SHA-256
 * 
 * @param data The data
 * @param datalen The length of the data
 * @param out The output
 * @return u32 The length of the output
 */
u32 openssl_hash_sha_256(u8 *data, u32 datalen, u8 *out);

/**
 * @brief Hashes the data using BLAKE2s-256
 * 
 * @param data The data
 * @param datalen The length of the data
 * @param out The output
 * @return u32 The length of the output
 */
u32 openssl_hash_blake2s_256(u8 *data, u32 datalen, u8 *out);

#endif