#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include "timer.h"

#define N_SAMPLES 100
#define KEY_BITS 2048

int main() {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, KEY_BITS, e, NULL);

    unsigned char msg[32] = "RSA test message!";
    unsigned char encrypted[256];
    unsigned long long *timings = malloc(N_SAMPLES * sizeof(unsigned long long));

    if (!timings) {
        perror("malloc");
        return 1;
    }

    for (int i = 0; i < N_SAMPLES; i++) {
        unsigned long long start = rdtsc();
        RSA_public_encrypt(sizeof(msg), msg, encrypted, rsa, RSA_PKCS1_PADDING);
        unsigned long long end = rdtsc();
        timings[i] = end - start;
    }

    FILE *f = fopen("rsa.txt", "w");
    if (!f) {
        perror("rsa.txt");
        free(timings);
        return 1;
    }
    double sum = 0;
    for (int i = 0; i < N_SAMPLES; i++) {
        fprintf(f, "%llu\n", timings[i]);
        sum += timings[i];
    }
    fclose(f);

    RSA_free(rsa);
    BN_free(e);
    free(timings);
    return 0;
}
