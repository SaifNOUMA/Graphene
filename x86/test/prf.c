
#include "../types.h"
// #include "../umac/common.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rand.h>

typedef struct {
    const char *name;
    u32 (*cipher)(u8*, u8*, u8*, u32, u8*);
} test_encrypt_t;

u32 openssl_aes_128_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
u32 openssl_aes_256_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out);
// u32 openssl_chacha20(u8 *key, u8)

static test_encrypt_t test_encrypts[] = {
    {"openssl_aes_128_ctr", openssl_aes_128_ctr},
    {"openssl_aes_256_ctr", openssl_aes_256_ctr},
};

int main(int argc, char **argv)
{
    u32 inlen = 16;
    u8 key[16] = {0xE8, 0x19, 0xEC, 0x74, 0x05, 0xD7, 0xB8, 0xAA, 0x22, 0x85, 0xB1, 0xAB, 0xF8, 0x03, 0xFB, 0x1E}, iv[16], in[16], out[16];
    if (RAND_bytes(key, 16) != 1) { return -1; }
    if (RAND_bytes(iv, 16) != 1) { return -1; }

    FILE *file = fopen("prng_put.out", "w"); // Open file in write mode
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    int counter = 0;
    for (u32 i = 0 ; i < 10000 ; i++) {
        memset(in, 0, 16);
        memcpy(in, (void*)&i, sizeof(u32));
        memset(out, 0, 16);

        openssl_aes_128_ctr(key, iv, in, inlen, out);

        for (size_t ind = 0; ind < 16; ind++) {
            for (int bit = 0; bit < 8; bit++) { // Iterate from the most significant bit to the least significant bit
                fprintf(file, "%d", (out[ind] >> bit) & 1);
                counter ++;

                if (counter % 25 == 0) 
                    fprintf(file, "\n   ");
            }
            // if ((ind+1) % 3 == 0)
            //     fprintf(file, "\n   "); // Space between bytes for readability
        }

        if (i < 500) {
            for (int ii = 0 ; ii < 16 ; ii++) {
                printf("%u ", out[ii]);
            }
            printf("\n");
        }
    }

    fclose(file);
    return 0;
}

u32 openssl_aes_128_ctr(u8 *key, u8 *iv, u8 *in, u32 inlen, u8 *out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0, len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &len, in, inlen);
    outlen = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    outlen += len;
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
    // EVP_EncryprFinal_ex(ctx, out + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}

