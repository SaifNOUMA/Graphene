
#ifndef _HMAC_H_
#define _HMAC_H_

#include "../types.h"

/**
 * @brief Computes the HMAC of the data using SHA-256
 * 
 * @param key The key
 * @param keylen The length of the key
 * @param data The data
 * @param datalen The length of the data
 * @param out The output
 * @return u32 The length of the output
 */
u32 openssl_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);

/**
 * @brief Computes the HMAC of the data using BLAKE2s-256
 * 
 * @param key The key
 * @param keylen The length of the key
 * @param data The data
 * @param datalen The length of the data
 * @param out The output
 * @return u32 The length of the output
 */
u32 openssl_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out);

#endif