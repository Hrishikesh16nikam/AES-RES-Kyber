#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "timer.h"

#define N_SAMPLES 1000

int main() {
    unsigned char pk[PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char ct[PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss[PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES];
    unsigned long long *timings = malloc(N_SAMPLES * sizeof(unsigned long long));

    if (!timings) {
        perror("malloc");
        return 1;
    }

    PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);

    for (int i = 0; i < N_SAMPLES; i++) {
        unsigned long long start = rdtsc();
        PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ct, ss, pk);
        unsigned long long end = rdtsc();
        timings[i] = end - start;
    }

    FILE *f = fopen("kyber.txt", "w");
    if (!f) {
        perror("kyber.txt");
        free(timings);
        return 1;
    }
    double sum = 0;
    for (int i = 0; i < N_SAMPLES; i++) {
        fprintf(f, "%llu\n", timings[i]);
        sum += timings[i];
    }
    fclose(f);
    free(timings);
    return 0;
}
