#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// Function to measure time
static double get_time(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

int main() {
    // Initialize variables
    unsigned char key[16] = {0};   // AES-128 key
    unsigned char iv[12] = {0};    // GCM IV
    unsigned char aad[16] = {0};   // Additional Authenticated Data
    unsigned char tag[16] = {0};   // GCM Tag
    unsigned char plaintext[16] = {0};  // Example plaintext
    unsigned char ciphertext[16] = {0};
    unsigned char hash_subkey[16]; // GHASH subkey (H)

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to allocate EVP_CIPHER_CTX\n");
        return 1;
    }

    // Generate random key and IV
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    // Initialize AES-GCM encryption
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    // Get GHASH subkey (H)
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(hash_subkey), hash_subkey);

    // Print the hash subkey
    printf("GHASH Subkey (H): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", hash_subkey[i]);
    }
    printf("\n");

    // Timing GHASH operation
    double start = get_time();
    for (int i = 0; i < 1000000; i++) { // Repeat for better timing accuracy
        GCM128_CONTEXT gcm;
        memset(&gcm, 0, sizeof(gcm));
        memcpy(gcm.H, hash_subkey, 16);  // Set GHASH subkey

        // Perform GHASH
        CRYPTO_gcm128_ghash(&gcm, aad, sizeof(aad));
    }
    double end = get_time();

    printf("Time taken for GHASH: %.6f seconds\n", end - start);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
