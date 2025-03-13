
#include <gcrypt.h>
#include "../types.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "../umac/common.h"
#include <libtomcrypt/tomcrypt.h>

typedef struct {
    const char *name;
    u32 (*cipher)(u8*, u8*, u8*, u32, u8*);
} test_encrypt_t;

u32 openssl_aes_128_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_192_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_256_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_128_gcm(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_128_gcm_aad(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_128_gcm_aad_tag(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_chachapoly_aad(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_192_gcm_aad(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_192_gcm(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_256_gcm_aad(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_256_gcm(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 gcrypt_aes_128_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 gcrypt_aes_256_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 libtomcrypt_aes_128_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 libtomcrypt_aes_256_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
int bench_prf(test_encrypt_t test_encrypt, u8 *key, u8 *iv, u32 bench_iterations, u32 datalen, double *cpu_time);

static test_encrypt_t test_encrypts[] = {
    {"openssl_aes_128_ctr", openssl_aes_128_ctr},
    {"openssl_aes_128_gcm", openssl_aes_128_gcm},
    // {"openssl_aes_128_gcm_aad", openssl_aes_128_gcm_aad},
    // {"openssl_aes_128_gcm_aad_tag", openssl_aes_128_gcm_aad_tag},
    // {"openssl_chachapoly_aad", openssl_chachapoly_aad},
    // {"openssl_aes_192_ctr", openssl_aes_192_ctr},
    // {"openssl_aes_256_ctr", openssl_aes_256_ctr},
    // {"openssl_aes_gcm_128", openssl_aes_128_gcm},
    // {"openssl_aes_gcm_192", openssl_aes_192_gcm},
    // {"openssl_aes_gcm_256", openssl_aes_256_gcm},
    // {"openssl_aes_gcm_128_aad", openssl_aes_128_gcm_aad},
    // {"openssl_aes_gcm_192_aad", openssl_aes_192_gcm_aad},
    // {"openssl_aes_gcm_256_aad", openssl_aes_256_gcm_aad},
};

int main(int argc, char **argv)
{
    u8 key[32], iv[16];
    u32 datalen = 1024;
    double cpu_time[128][128];
    u32 bench_iterations = 1000;


    if (RAND_bytes(key, 16) != 1) { return -1; }
    if (RAND_bytes(iv, 16) != 1) { return -1; }
    
    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { datalen = atoi(argv[2]); }

    register_cipher(&aes_desc);

    // u32 datalens[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768};
    u32 datalens[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};

    for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    {
        for (u32 idx = 0 ; idx < sizeof(test_encrypts)/sizeof(test_encrypt_t) ; idx++)
        {   
            if (bench_prf(test_encrypts[idx], key, iv, bench_iterations, datalens[i], &cpu_time[idx][i]) != 0) { return -1; }
        }
    }

    // for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    //     bench_aad(test_encrypts[1], key, iv, bench_iterations, 32, &cpu_time[1][i]);

    save_to_csv("bench_prf.csv", sizeof(test_encrypts)/sizeof(test_encrypt_t), sizeof(datalens)/sizeof(u32), cpu_time);
    return 0;
}


// implementation
int bench_prf(test_encrypt_t test_encrypt, u8 *key, u8 *iv, u32 bench_iterations, u32 datalen, double *cpu_time)
{
    u8 in[datalen], out[datalen+32];
    double _cpu_time = 0;
    struct timespec t0, t1;


    if (RAND_bytes(in, datalen) != 1) { return -1; }
    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        memset(out, 0, datalen);

        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (test_encrypt.cipher(key, iv, in, datalen, out) != datalen) { return -1; }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    }
    *cpu_time = _cpu_time / bench_iterations;
    printf("%s: %.0f ns\n", test_encrypt.name, _cpu_time / bench_iterations);

    return 0;
}

int bench_aad(test_encrypt_t test_encrypt, u8 *key, u8 *iv, u32 bench_iterations, u32 datalen, double *cpu_time)
{
    u8 in[datalen], out[datalen+32];
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;
    u8 tag[16] = {0};
    u8 aad[16] = {0};
    int len;
    double _cpu_time = 0;
    struct timespec t0, t1;

    if (RAND_bytes(in, datalen) != 1) { return -1; }

    if (!(ctx = EVP_CIPHER_CTX_new())) { return -1; }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) { return -1; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVP_MAX_IV_LENGTH, NULL) != 1) { return -1; } 
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) { return -1; }
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, 16)) { return -1; }
    if (1 != EVP_EncryptUpdate(ctx, out, &len, in, datalen)) { return -1; }
    outlen = len;
    if (1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) { return -1; }
    outlen += len;

    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        memset(out, 0, datalen);
        memset(tag, 0, 16);

        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) { return -1; }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    }
    *cpu_time = _cpu_time / bench_iterations;
    printf("%s: %.0f ns\n", test_encrypt.name, _cpu_time / bench_iterations);
    printf("tag: ");
    for (u32 i = 0; i < 16; i++) { printf("%02x", tag[i]); }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

u32 libtomcrypt_aes_128_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    symmetric_CTR ctr;
    u32 outlen = 0;

    if (ctr_start(find_cipher("aes"), iv, key, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr) != CRYPT_OK) { return -1; }
    if (ctr_encrypt(in, out, inlen, &ctr) != CRYPT_OK) { return -1; }
    if (ctr_done(&ctr) != CRYPT_OK) { return -1; }

    return inlen;
}

u32 libtomcrypt_aes_256_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    symmetric_CTR ctr;
    u32 outlen = 0;

    if (ctr_start(find_cipher("aes"), iv, key, 32, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr) != CRYPT_OK) { return -1; }
    if (ctr_encrypt(in, out, inlen, &ctr) != CRYPT_OK) { return -1; }
    if (ctr_done(&ctr) != CRYPT_OK) { return -1; }

    return inlen;
}

u32 openssl_aes_128_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &outlen, in, inlen);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}


u32 openssl_aes_192_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_192_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &outlen, in, inlen);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}


u32 openssl_aes_128_gcm(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &outlen, in, inlen);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}


u32 openssl_chachapoly_aad(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;
    u8 tag[16] = {0};
    u8 aad[16] = {0};
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVP_MAX_IV_LENGTH, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, NULL, &len, aad, 16);
    EVP_EncryptUpdate(ctx, out, &len, in, inlen);
    outlen = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    outlen += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) { return -1; }
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}


u32 openssl_aes_128_gcm_aad(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;
    u8 tag[16] = {0};
    u8 aad[16] = {0};
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVP_MAX_IV_LENGTH, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, NULL, &len, aad, 16);
    EVP_EncryptUpdate(ctx, out, &len, in, inlen);
    outlen = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    outlen += len;
    // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}

u32 openssl_aes_128_gcm_aad_tag(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;
    u8 tag[16] = {0};
    u8 aad[16] = {0};
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVP_MAX_IV_LENGTH, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, NULL, &len, aad, 16);
    EVP_EncryptUpdate(ctx, out, &len, in, inlen);
    outlen = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    outlen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}

u32 openssl_aes_192_gcm_aad(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;
    u8 tag[16] = {0};
    u8 aad[16] = {0};
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVP_MAX_IV_LENGTH, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, NULL, &len, aad, 16);
    EVP_EncryptUpdate(ctx, out, &len, in, inlen);
    outlen = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    outlen += len;
    // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}


u32 openssl_aes_256_gcm_aad(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;
    u8 tag[16] = {0};
    u8 aad[16] = {0};
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVP_MAX_IV_LENGTH, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    // EVP_EncryptUpdate(ctx, NULL, &len, aad, 16);
    EVP_EncryptUpdate(ctx, out, &len, in, inlen);
    outlen = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    outlen += len;
    // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}


u32 openssl_aes_192_gcm(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &outlen, in, inlen);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}

u32 openssl_aes_256_gcm(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &outlen, in, inlen);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}

u32 openssl_aes_256_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    u32 outlen = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &outlen, in, inlen);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}

u32 gcrypt_aes_128_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    gcry_cipher_hd_t hd;
    u32 outlen = 0;

    gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0);
    gcry_cipher_setkey(hd, key, 16);
    gcry_cipher_setiv(hd, iv, 16);
    gcry_cipher_encrypt(hd, out, inlen, in, inlen);
    gcry_cipher_close(hd);

    return inlen;
}

u32 gcrypt_aes_256_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    gcry_cipher_hd_t hd;
    u32 outlen = 0;

    gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0);
    gcry_cipher_setkey(hd, key, 16);
    gcry_cipher_setiv(hd, iv, 16);
    gcry_cipher_encrypt(hd, out, inlen, in, inlen);
    gcry_cipher_close(hd);

    return inlen;
}
