#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include "api.h"

#define SERVER_IP "10.188.58.133"
#define SERVER_PORT 13000
#define AES_BLOCK_SIZE 16

void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int recv_all(int sock, void *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t r = recv(sock, (char*)buf + recvd, len - recvd, 0);
        if (r <= 0) return -1;
        recvd += r;
    }
    return 0;
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) handle_error("Socket creation failed");
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0)
        handle_error("Invalid address");
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        handle_error("Connection failed");

    printf("[+] Connected to %s:%d\n", SERVER_IP, SERVER_PORT);

    unsigned char pk[PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES];
    if (PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk) != 0)
        handle_error("Keypair generation failed");

    int pk_size = sizeof(pk);
    send(sockfd, &pk_size, sizeof(pk_size), 0);
    send(sockfd, pk, pk_size, 0);
    printf("[+] Sent Kyber pk (%d bytes)\n", pk_size);

    int ct_size;
    recv_all(sockfd, &ct_size, sizeof(ct_size));
    unsigned char ct[PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    recv_all(sockfd, ct, ct_size);
    printf("[+] Received ct (%d bytes)\n", ct_size);

    unsigned char ss[PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss, ct, sk) != 0)
        handle_error("Decapsulation failed");
    printf("[+] Derived ss (%d bytes)\n", (int)sizeof(ss));

    unsigned char enc[AES_BLOCK_SIZE];
    recv_all(sockfd, enc, AES_BLOCK_SIZE);
    printf("[+] Received encrypted secret (%d bytes)\n", AES_BLOCK_SIZE);

    AES_KEY dec;
    if (AES_set_decrypt_key(ss, 128, &dec) < 0)
        handle_error("AES_set_decrypt_key failed");
    unsigned char secret[AES_BLOCK_SIZE + 1];
    AES_decrypt(enc, secret, &dec);
    secret[AES_BLOCK_SIZE] = '\0';

    printf("Decrypted (hex): ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) printf("%02x", secret[i]);
    printf("\n");
    printf("Decrypted (ascii): %s\n", secret);

    FILE *fp = fopen("secret_kyber.txt", "w");
    if (!fp) handle_error("Failed to open secret_kyber.txt");
    fprintf(fp, "%s", secret);
    fclose(fp);

    close(sockfd);
    return 0;
}
