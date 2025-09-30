#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "api.h"
#include "timer.h"

#define NAES   10000
#define NRSA   1000
#define NKYBER 1000

static double bench_aes(void) {
    unsigned char key[16]={0}, in[16]={0}, out[16];
    AES_KEY enc; AES_set_encrypt_key(key,128,&enc);
    FILE *f = fopen("aes.txt", "w");
    uint64_t t0,t1; double sum=0.0;
    for (int i=0;i<NAES;i++){
        t0=rdtsc();
        AES_encrypt(in,out,&enc);
        t1=rdtsc();
        double cycles = (double)(t1-t0);
        fprintf(f, "%.2f\n", cycles);
        sum += cycles;
    }
    fclose(f);
    return sum/NAES;
}

static double bench_rsa(void) {
    BIGNUM *e = BN_new(); RSA *rsa = RSA_new(); BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    unsigned char in[32]; unsigned char out[4096]; RAND_bytes(in,sizeof(in));
    FILE *f = fopen("rsa.txt", "w");
    uint64_t t0,t1; double sum=0.0;
    for (int i=0;i<NRSA;i++){
        t0=rdtsc();
        int r=RSA_public_encrypt(sizeof(in),in,out,rsa,RSA_PKCS1_OAEP_PADDING);
        t1=rdtsc();
        if(r<=0){ break; }
        double cycles = (double)(t1-t0);
        fprintf(f, "%.2f\n", cycles);
        sum += cycles;
    }
    fclose(f);
    RSA_free(rsa); BN_free(e);
    return sum/NRSA;
}

static double bench_kyber(void) {
    uint8_t pk[PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES];
    PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);
    FILE *f = fopen("kyber.txt", "w");
    uint64_t t0,t1; double sum=0.0;
    for (int i=0;i<NKYBER;i++){
        t0=rdtsc();
        PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ct, ss, pk);
        t1=rdtsc();
        double cycles = (double)(t1-t0);
        fprintf(f, "%.2f\n", cycles);
        sum += cycles;
    }
    fclose(f);
    return sum/NKYBER;
}

int main(void) {
    double a = bench_aes();
    double r = bench_rsa();
    double k = bench_kyber();
    printf("AES mean cycles: %.2f\n", a);
    printf("RSA mean cycles: %.2f\n", r);
    printf("Kyber mean cycles: %.2f\n", k);
    return 0;
}
