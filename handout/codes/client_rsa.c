#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define SERVER_IP "10.188.58.133"
#define SERVER_PORT 12000
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

void handle_error(const char *msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned char buffer[4096];
    RSA *server_pubkey = NULL;
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char encrypted_aes_key[512];
    unsigned char encrypted_msg[AES_BLOCK_SIZE];
    unsigned char decrypted_msg[AES_BLOCK_SIZE + 1] = {0}; 
    int ret;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

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

    int key_size;
    if (recv(sockfd, &key_size, sizeof(key_size), 0) != sizeof(key_size))
        handle_error("Failed to read key size");

    if (recv(sockfd, buffer, key_size, 0) != key_size)
        handle_error("Failed to read public key");

    BIO *keybio = BIO_new_mem_buf(buffer, key_size);
    server_pubkey = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    BIO_free(keybio);
    if (!server_pubkey) handle_error("Failed to load public key");

    if (!RAND_bytes(aes_key, AES_KEY_SIZE))
        handle_error("Failed to generate AES key");

    ret = RSA_public_encrypt(AES_KEY_SIZE, aes_key, encrypted_aes_key,
                             server_pubkey, RSA_PKCS1_PADDING);
    if (ret == -1) handle_error("Failed to encrypt AES key");

    send(sockfd, &ret, sizeof(int), 0);
    send(sockfd, encrypted_aes_key, ret, 0);
    printf("[+] Sent encrypted AES key (%d bytes)\n", ret);

    ssize_t bytes_read = recv(sockfd, encrypted_msg, AES_BLOCK_SIZE, 0);
    if (bytes_read <= 0) handle_error("Failed to read encrypted message");
    printf("[+] Received encrypted secret (%zd bytes)\n", bytes_read);

    AES_KEY aes_dec_key;
    if (AES_set_decrypt_key(aes_key, 128, &aes_dec_key) < 0)
        handle_error("Failed to set AES decryption key");
    AES_ecb_encrypt(encrypted_msg, decrypted_msg, &aes_dec_key, AES_DECRYPT);
    decrypted_msg[AES_BLOCK_SIZE] = '\0';

    printf("Decrypted (hex): ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) printf("%02x", decrypted_msg[i]);
    printf("\n");
    printf("Decrypted (ascii): %s\n", decrypted_msg);

    FILE *fp = fopen("secret_rsa.txt", "w");
    if (!fp) handle_error("Failed to open secret_rsa.txt");
    fprintf(fp, "%s", decrypted_msg);
    fclose(fp);

    RSA_free(server_pubkey);
    close(sockfd);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
