
#include <string.h>
#include "hash.h"
#include "hmac.h"
#include "fae.h"
#include "../types.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

void save_to_csv(const char *filename, u32 rows, u32 cols, double array[128][128]);

u32 tester(char *enc_algorithm, char *auth_algorithm, char *upd_algorithm, u32 inlen, u32 numiterations, u32 batch_sizem, double *enc_time, double *auth_time, double *agg_time, double *upd_time);

int main(int argc, char *argv[])
{
    fae_ctx_t fae_ctx;
    fae_out_t fae_out;
    u32 ptlen, inlen = 1024, numiterations = 100;
    u32 batch_size = 1, counter = 0;
    double cpu_time[128][128] = {0};

    if (argc > 1) { inlen = atoi(argv[1]); }
    if (argc > 2) { numiterations = atoi(argv[2]); }
    if (argc > 3) { batch_size = atoi(argv[3]); }

    char *enc_algorithms[]  = {"aes-128-ctr", "aes-256-ctr"};
    char *auth_algorithms[] = {"hmac-sha-256", "hmac-blake2s-256"};
    char *upd_algorithms[]  = {"sha-256", "blake2s-256"};

    for (int i = 0 ; i < sizeof(enc_algorithms)/sizeof(char*) ; i++) {
        for (int j = 0 ; j < sizeof(auth_algorithms)/sizeof(char*) ; j++) {
            for (int k = 0 ; k < sizeof(upd_algorithms)/sizeof(char*) ; k++) {
                if (tester(enc_algorithms[i], auth_algorithms[j], upd_algorithms[k], inlen, numiterations, batch_size, &cpu_time[counter][0], &cpu_time[counter][1], &cpu_time[counter][2], &cpu_time[counter][3]) != 0)
                {
                    return -1; 
                }
                counter ++;
            }
        }
    }
    save_to_csv("cpu_time.csv", counter+1, 4, cpu_time);
    return 0;
}
 
u32 tester(char *enc_algorithm, char *auth_algorithm, char *upd_algorithm, u32 inlen, u32 numiterations, u32 batch_size,
           double *enc_time, double *auth_time, double *agg_time, double *upd_time)
{
    fae_ctx_t fae_ctx;
    fae_out_t fae_out;
    u32 ptlen;
    u8 in[inlen];
    u8 pt[inlen+16];

    fae_ctx.enc_time = fae_ctx.auth_time = fae_ctx.agg_time = fae_ctx.upd_time = 0;

    if (RAND_bytes(in, inlen) != 1) { return -1; }

    if (fae_kg(&fae_ctx, enc_algorithm, auth_algorithm, upd_algorithm) != 0) { return -1; }
    memset(fae_out.agg_sig, 0, 32);

    for (int iter = 0 ; iter < numiterations ; iter++) {
        for (int i = 0 ; i < batch_size ; i++) {
            if (fae_enc(&fae_ctx, in, inlen, &fae_out) != 0) { return -1; }
            if (fae_dec(&fae_ctx, pt, &ptlen, &fae_out) != 0) { return -1; }
            if (fae_upd(&fae_ctx)) { return -1; }

            if (memcmp(in, pt, inlen) != 0) {
                printf("ERROR: data mismatch\n");
                return -1;
            }
        }
    }

    *enc_time   = fae_ctx.enc_time / numiterations;
    *agg_time   = fae_ctx.agg_time / numiterations;
    *upd_time   = fae_ctx.upd_time / numiterations;
    *auth_time  = fae_ctx.auth_time / numiterations;

    printf("enc_algorithm: %s ; auth_algorithm: %s ; upd_algorithm: %s\n", enc_algorithm, auth_algorithm, upd_algorithm);
    printf("avg enc  time: %.0f ns\n", fae_ctx.enc_time / numiterations);
    printf("avg auth time: %.0f ns\n", fae_ctx.auth_time / numiterations);
    printf("avg agg  time: %.0f ns\n", fae_ctx.agg_time / numiterations);
    printf("avg upd  time: %.0f ns\n", fae_ctx.upd_time / numiterations);
    printf("%.0f & %.0f & %.0f & %.0f\n", fae_ctx.enc_time / numiterations, fae_ctx.auth_time / numiterations, fae_ctx.agg_time / numiterations, fae_ctx.upd_time / numiterations);
    printf("\n");

    EVP_CIPHER_CTX_free(fae_ctx.evp_cipher_ctx);
    return 0;
}

void save_to_csv(const char *filename, u32 rows, u32 cols, double array[128][128]) {
    FILE *fp = fopen(filename, "a");

    if (fp == NULL) {
        perror("Unable to open file for writing");
        return;
    }

    for (u32 i = 0; i < rows; i++) {
        for (u32 j = 0; j < cols; j++) {
            fprintf(fp, "%.0f", array[i][j]);
            if (j < cols - 1) {
                fprintf(fp, " & ");
            }
        }
        fprintf(fp, " \\\\ \n");
    }

    fclose(fp);
}
