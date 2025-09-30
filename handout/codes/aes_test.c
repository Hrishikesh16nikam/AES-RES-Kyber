#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include "timer.h"

#define N_SAMPLES 1000

int main() {
    unsigned char key[16] = "0123456789abcdef";
    unsigned char input[16] = "HelloAES1234567";
    unsigned char output[16];
    AES_KEY aes_key;
    unsigned long long *timings = malloc(N_SAMPLES * sizeof(unsigned long long));

    if (!timings) {
        perror("malloc");
        return 1;
    }

    AES_set_encrypt_key(key, 128, &aes_key);

    for (int i = 0; i < N_SAMPLES; i++) {
        unsigned long long start = rdtsc();
        AES_encrypt(input, output, &aes_key);
        unsigned long long end = rdtsc();
        timings[i] = end - start;
    }

    // Write all timings once at the end
    FILE *f = fopen("aes.txt", "w");
    if (!f) {
        perror("aes.txt");
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
