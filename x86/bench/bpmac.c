
#include "../types.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <libtomcrypt/tomcrypt.h>
#include "../umac/common.h"
#include <gcrypt.h>

#if (IS_ZOUL==0) // Zoleratia z1
#define SIZEOF_INT 2
#elif (IS_ZOUL==1) // Zolertia borad
#define SIZEOF_INT 4
#endif

#define MAC_LEN 16
#define MAC_LEN_IN_INT (MAC_LEN/sizeof(int))
#define INT_SIZE sizeof(int)

typedef struct pre_ctx_t{

  unsigned char mac_key[16];
  int default_msg[MAC_LEN/INT_SIZE];
  int res[MAC_LEN/INT_SIZE];
  int* bit_flips;//[30*8* (16/sizeof(int))];
  int max_len;

  uint8_t nonce_cache[16];
  uint8_t prev_nonce[16];
  uint8_t nonce_key[32];

} bpmac_ctx_t;

static void pbuf(void *buf, int n, char *s)
{
    int i;
    char *cp = (char *)buf;

    if (n <= 0 || n >= 30)
        n = 30;

    if (s)
        printf("%s: ", s);

    for (i = 0; i < n; i++)
        printf("%02X", (unsigned char)cp[i]);
    printf("\n");
}

void bpmac_init( char* key,  char* nonce_key, int max_size, bpmac_ctx_t* ctx){

    uint32_t i,j;

    //ctx->bit_flips = (int*) malloc( 8*max_size*MAC_LEN );
    //if (ctx->bit_flips == 0){
    //	printf("Failed to allocate memory for bitflit MACs\n");
    //}

    memset(ctx->res, 0, MAC_LEN);
    memset(ctx->default_msg, 0, MAC_LEN);

    memcpy( ctx->mac_key, key, 16 );
    memcpy( ctx->nonce_key, nonce_key, 16 );

    memset(ctx->prev_nonce, 0, 16);
    memset(ctx->nonce_cache, 0, 16);

    // dtls_hmac_context_t* hmac_ctx = dtls_hmac_new( (unsigned char*) key, 16 );

    ctx->max_len = max_size*8+1;

    unsigned char output0[32];
    unsigned char output1[32];

    ctx->bit_flips = (int*)malloc((max_size*8+1)*MAC_LEN);
    if(! ctx->bit_flips){
        printf("Error: Could not allocate memory for bitflips MACs\n");
    }

    for(i=0; i<max_size*8 +1; i++){

        // dtls_hmac_init(hmac_ctx, ctx->mac_key, 16);

    	// uint32_t input = 2*i;

        // dtls_hmac_update(hmac_ctx, (unsigned char*)&input, 4);
        // dtls_hmac_finalize(hmac_ctx, output0);


        // dtls_hmac_init(hmac_ctx, ctx->mac_key, 16);


        // input += 1;

        // dtls_hmac_update(hmac_ctx, (unsigned char*)&input, 4);
        // dtls_hmac_finalize(hmac_ctx, output1);

    	for(j=0; j<MAC_LEN_IN_INT; j++){
    	    ctx->default_msg[j] ^= ((int*)output0)[j];

    	    ctx->bit_flips[  i*MAC_LEN_IN_INT + j] = ((int*)output0)[j] ^ ((int*)output1)[j];
    	}
    }


    // dtls_hmac_free(hmac_ctx);


}


void xor_tags(void* tag, void* value) {

#if (MAC_LEN == 4)
    *((uint32_t *)tag) ^= *((uint32_t *)value);
#elif (MAC_LEN == 8)
    *((uint64_t *)tag) ^= *((uint64_t *)value);
#elif (MAC_LEN == 12)
    ((uint64_t *)tag)[0] ^= ((uint64_t *)value)[0];
    ((uint32_t *)tag)[2] ^= ((uint32_t *)value)[2];
#elif (MAC_LEN == 16)
    ((uint64_t *)tag)[0] ^= ((uint64_t *)value)[0];
    ((uint64_t *)tag)[1] ^= ((uint64_t *)value)[1];
#endif

}


void bpmac_sign(bpmac_ctx_t* ctx, char* msg, int len,  char* tag) {

    memcpy(tag, ctx->res, 16);

    int index = 0;
    int i,j;

    /* For each byte in the message*/
    for(i=0; i < len; ++i){
    	/* For each bit in that byte*/
        for(j=0; j < 8; ++j){
	        /* If that bit is set */
            if( msg[i] & (1<<(7-j)) ){
                /* current MAC XOR bitflip MAC */
                xor_tags( tag, &ctx->bit_flips[i*8+j] );
            }
            // index += MAC_LEN_IN_INT; // Optimization: Computing the index like this, and not more complicatly only when bit is set, is on average slightly faster and decreases variance
        }
    }

    /* Add 1 padding bit */
    xor_tags( tag, &(ctx->bit_flips[index]));
}


void bpmac_pre(bpmac_ctx_t* ctx, uint8_t nonce[8])
{
    /* 'index' indicates that we'll be using the 0th or 1st eight bytes
     * of the AES output. If last time around we returned the index-1st
     * element, then we may have the result in the cache already.
     */

#if (MAC_LEN == 4)
#define LOW_BIT_MASK 3
#elif (MAC_LEN == 8)
#define LOW_BIT_MASK 1
#elif (MAC_LEN > 8)
#define LOW_BIT_MASK 0
#endif

    uint8_t tmp_nonce_lo[4];

#if (MAC_LEN < 12)
    int index = nonce[7] & LOW_BIT_MASK;
#else
    int index = 0;
#endif
    *(uint32_t *)tmp_nonce_lo = ((uint32_t *)nonce)[1];
    tmp_nonce_lo[3] &= ~LOW_BIT_MASK; /* zero last bit */

    if ( (((uint32_t *)tmp_nonce_lo)[0] != ((uint32_t *)ctx->prev_nonce)[1]) ||
         (((uint32_t *)nonce)[0] != ((uint32_t *)ctx->prev_nonce)[0]) )
    {
        ((uint32_t *)ctx->prev_nonce)[0] = ((uint32_t *)nonce)[0];
        ((uint32_t *)ctx->prev_nonce)[1] = ((uint32_t *)tmp_nonce_lo)[0];

        // rijndaelEncrypt( (const uint32_t*) ctx->nonce_key, 10, nonce, ctx->nonce_cache);

    }

    int k;
    for(k=0; k<MAC_LEN_IN_INT; k++){
        ((int*)ctx->default_msg)[k] ^= ((int*)ctx->nonce_cache)[k+index*MAC_LEN_IN_INT];
    }
}

int bpmac_vrfy( char* msg, int size, char* sig, bpmac_ctx_t* ctx){

    char output[32];

    bpmac_sign(ctx, msg, size, output);

    return memcmp( sig, output, 16 );
}

void bpmac_deinit(bpmac_ctx_t* ctx){

    free(ctx->bit_flips);

}

void bpmac_test(){
    bpmac_ctx_t ctx;

    char nonce[] = "abcdefgh";
    char tag[16] = {0};
    int lengths[] = {1,2,4,8,16,32,64,128, 256, 512, 1024, 2048, 4096};
    char data_ptr[4096];

    int i, bench_iterations = 100000;
    double _cpu_time;
    struct timespec t0, t1;
    char key[] =  "abcdefghijklmnop";
    char key2[] = "ponmlkjihgfedcba";

    for (i = 0; i < sizeof(lengths)/sizeof(*lengths); i++) {
        _cpu_time = 0;
	    bpmac_init(key, key2, lengths[i], &ctx);
    	bpmac_pre(&ctx, (uint8_t*)nonce);

        for (int j = 0 ; j < bench_iterations ; j++) {
            RAND_bytes(data_ptr, lengths[i]);

            clock_gettime(CLOCK_MONOTONIC, &t0);
        	bpmac_sign(&ctx, data_ptr, lengths[i], tag);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
        }

	    bpmac_deinit(&ctx);
        printf("BPMAC(inlen=%4u) = %.0f us\n", lengths[i], _cpu_time / (bench_iterations * 1e-6));
    }
}

int main(int argc, char **argv)
{
    u32 bench_iterations = 1000;
    u32 datalen = 1024;
    double cpu_time[128][128];
    
    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { datalen = atoi(argv[2]); }

    u32 datalens[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072};

    bpmac_test();

    // for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    // {
    //     for (u32 idx = 0; idx < sizeof(test_hmacs)/sizeof(test_hmac_t); idx++) {
    //         if (bench_hmac(bench_iterations, datalens[i], test_hmacs[idx], &cpu_time[idx][i]) != 0) { return -1; }
    //     }
    // }

    // save_to_csv("bench_hmac.csv", sizeof(test_hmacs)/sizeof(test_hmac_t), sizeof(datalens)/sizeof(u32), cpu_time);

    return 0;
}

// implementation
// static int bench_hmac(u32 bench_iterations, u32 datalen, test_hmac_t test_hmac, double *cpu_time)
// {
//     double _cpu_time;
//     struct timespec t0, t1;
//     u32 outlen = 16;
//     u32 keylen = 16;
//     u32 noncelen = 16;
//     int bit;

//     u8 *in, *out, *key, *nonce, byte;

//     // keylen = test_hmac.keylen;
//     // outlen = test_hmac.outlen;
//     in  = (u8*) malloc(datalen);
//     out = (u8*) malloc(test_hmac.outlen);
//     key = (u8*) malloc(keylen);
//     nonce = (u8*) malloc(16);

//     if (RAND_bytes(in, datalen) != 1) { return -1; }
//     if (RAND_bytes(key, keylen) != 1) { return -1; }
//     if (RAND_bytes(nonce, keylen) != 1) { return -1; }

//     _cpu_time = 0;
//     clock_gettime(CLOCK_MONOTONIC, &t0);

//     for (u32 iter = 0 ; iter < bench_iterations ; iter++)
//     {
//         for (int i  = 0; i < 16; i++) {
//             byte = nonce[i];
//             bit = 0;
//             while (bit < 8) {
//                 bit = byte & 1;
//                 byte >>= 1;

//                 if (bit) {
//                     for (int j = 0; j < 16; j++) {
//                         out[j] ^= key[j];
//                     }
//                 }
//             }
//         }
//         // if (test_hmac.hmac(key, keylen, in, datalen, out) != 0) { return -1; }

//     }

//     clock_gettime(CLOCK_MONOTONIC, &t1);
//     _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;

//     printf("HMAC(%11s,inlen=%4u) = %.6f ms\n", test_hmac.name, datalen, _cpu_time / bench_iterations);
//     *cpu_time = _cpu_time * 1e6 / bench_iterations;

//     free(in);
//     free(out);
//     free(key);

//     return 0;
// }

u32 gcrypt_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 32;

    gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    gcry_md_setkey(hd, key, keylen);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_SHA256), outlen);
    gcry_md_close(hd);

    return 0;
}

u32 gcrypt_hmac_sha_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 64;

    gcry_md_open(&hd, GCRY_MD_SHA512, 0);
    gcry_md_setkey(hd, key, keylen);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_SHA512), outlen);
    gcry_md_close(hd);

    return 0;
}

u32 gcrypt_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 32;

    gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0);
    gcry_md_setkey(hd, key, keylen);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_BLAKE2S_256), outlen);
    gcry_md_close(hd);

    return 0;
}

u32 gcrypt_hmac_blake2b_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    gcry_md_hd_t hd;
    u32 outlen = 64;

    gcry_md_open(&hd, GCRY_MD_BLAKE2B_512, 0);
    gcry_md_setkey(hd, key, keylen);
    gcry_md_write(hd, data, datalen);
    memcpy(out, gcry_md_read(hd, GCRY_MD_BLAKE2B_512), outlen);
    gcry_md_close(hd);

    return 0;
}

u32 openssl_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen;

    if (HMAC(EVP_sha256(), key, keylen, data, datalen, out, &outlen) == NULL) { return -1; }

    return 0;
}

u32 openssl_hmac_sha_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen;

    if (HMAC(EVP_sha512(), key, keylen, data, datalen, out, &outlen) == NULL) { return -1; }

    return 0;
}

u32 openssl_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen;

    if (HMAC(EVP_blake2s256(), key, keylen, data, datalen, out, &outlen) == NULL) { return -1; }

    return 0;
}

u32 openssl_hmac_blake2b_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    u32 outlen;

    if (HMAC(EVP_blake2b512(), key, keylen, data, datalen, out, &outlen) == NULL) { return -1; }

    return 0;
}

u32 libtomcrypt_hmac_sha_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    hmac_state state;
    unsigned long outlen = 32;

    if (hmac_init(&state, find_hash("sha256"), key, keylen) != CRYPT_OK) { return -1; }
    if (hmac_process(&state, data, datalen) != CRYPT_OK) { return -1; } 
    if (hmac_done(&state, out, &outlen) != CRYPT_OK) { return -1; }

    return 0;
}

u32 libtomcrypt_hmac_sha_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    hmac_state state;
    unsigned long outlen = 64;

    if (hmac_init(&state, find_hash("sha512"), key, keylen) != CRYPT_OK) { return -1; }
    if (hmac_process(&state, data, datalen) != CRYPT_OK) { return -1; }
    if (hmac_done(&state, out, &outlen) != CRYPT_OK) { return -1; }

    return 0;
}

u32 libtomcrypt_hmac_blake2s_256(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    hmac_state state;
    unsigned long outlen = 32;

    if (hmac_init(&state, find_hash("blake2s-256"), key, keylen) != CRYPT_OK) { return -1; }
    if (hmac_process(&state, data, datalen) != CRYPT_OK) { return -1; }
    if (hmac_done(&state, out, &outlen) != CRYPT_OK) { return -1; }

    return 0;
}

u32 libtomcrypt_hmac_blake2b_512(u8 *key, u32 keylen, u8 *data, u32 datalen, u8 *out)
{
    hmac_state state;
    unsigned long outlen = 64;

    if (hmac_init(&state, find_hash("blake2b-512"), key, keylen) != CRYPT_OK) { return -1; }
    if (hmac_process(&state, data, datalen) != CRYPT_OK) { return -1; }
    if (hmac_done(&state, out, &outlen) != CRYPT_OK) { return -1; }

    return 0;
}
