
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <gcrypt.h>
#include "../umac/common.h"

static int bench_chacha_poly1305_ssl(u32 bench_iterations, u32 datalen, double *cpu_time);

int main(int argc, char **argv)
{
    u32 bench_iterations = 1000;
    u32 datalen = 1024;
    u32 batch_size = 100;
    double cpu_time[128][128];

    if (argc > 1) { bench_iterations = atoi(argv[1]); }
    if (argc > 2) { datalen = atoi(argv[2]); }
    if (argc > 3) { batch_size = atoi(argv[3]); }

    u32 datalens[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};

    for (u32 i = 0; i < sizeof(datalens)/sizeof(u32); i++)
    {
        if (bench_chacha_poly1305_ssl(bench_iterations, datalens[i], &cpu_time[0][i]) != 0) { return -1; }
    }

    save_to_csv("bench_chacha_poly1305.csv", 1, sizeof(datalens)/sizeof(u32), cpu_time);

    return 0;
}

// implementation
static int bench_chacha_poly1305_ssl(u32 bench_iterations, u32 datalen, double *cpu_time)
{
    double _cpu_time;
    struct timespec t0, t1;
    u32 outlen = 16;
    u32 keylen = 32;
    u32 len;
    u8 *in, *out, key[keylen], iv[16], aad[16], tag[16];
    EVP_CIPHER_CTX *chachapoly_ctx;
    in  = (u8*) malloc(datalen);
    out = (u8*) malloc(datalen);
    memset(tag, 0, 16);

    chachapoly_ctx = EVP_CIPHER_CTX_new();
    if (chachapoly_ctx == NULL) { return -1; }

    if (RAND_bytes(in, datalen) != 1) { return -1; }
    if (RAND_bytes(key, keylen) != 1) { return -1; }

    _cpu_time = 0;
    for (u32 iter = 0 ; iter < bench_iterations ; iter++)
    {
        memset(tag, 0, 16);
        
        clock_gettime(CLOCK_REALTIME, &t0);

        if (EVP_EncryptInit_ex(chachapoly_ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) { return -1; }
        if (EVP_EncryptInit_ex(chachapoly_ctx, NULL, NULL, key, iv) != 1) { return -1; }
        if (EVP_EncryptUpdate(chachapoly_ctx, NULL, &len, aad, 16) != 1) { return -1; }
        if (EVP_EncryptUpdate(chachapoly_ctx, out, &len, in, datalen) != 1) { return -1; }
        if (EVP_EncryptFinal_ex(chachapoly_ctx, out, &len) != 1) { return -1; }
        if (EVP_CIPHER_CTX_ctrl(chachapoly_ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1) { return -1; }

        clock_gettime(CLOCK_REALTIME, &t1);
        _cpu_time += (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }

    // print tag
    printf("tag: ");
    for (u32 i = 0; i < 16; i++) { printf("%02x", tag[i]); }
    printf("\n");

    *cpu_time = _cpu_time * 1e6 / bench_iterations;
    printf("CHACHA-POLY1305 (SSL, inlen=%4u) : %.6f ms\n", datalen, _cpu_time / bench_iterations);

    free(in);
    free(out);
    EVP_CIPHER_CTX_free(chachapoly_ctx);
    return 0;
}
