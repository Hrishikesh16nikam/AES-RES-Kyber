#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include "kyber512/api.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>

AES_KEY *expanded;

uint8_t secret[16] = {
    0xb2, 0x01, 0x12, 0x93,
    0xe9, 0x55, 0x26, 0xa7,
    0xea, 0x69, 0x3a, 0xcb,
    0xfc, 0x7d, 0x0e, 0x1f
};

/**
 * Configuration.
 */
struct Config
{
  uint16_t port_;
};

int kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk){
  int result = PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ct, ss, pk);
  return result;
}

void printHelp(char *argv[])
{
  fprintf(
      stderr,
      "Usage: %s [-p port number] "
      "\n",
      argv[0]);
  exit(EXIT_FAILURE);
}

void parseOpt(int argc, char *argv[], struct Config *config)
{
  int opt;
  while ((opt = getopt(argc, argv, "p:")) != -1)
  {
    switch (opt)
    {
    case 'p':
      config->port_ = atoi(optarg);
      break;
    default:
      printHelp(argv);
    }
  }
}

/**
 * Set a read timeout.
 *
 * @param sk Socket.
 * @return True if successful.
 */
static bool SetReadTimeout(const int sk)
{
  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  if (setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
  {
    printf("Unable to set read timeout\n");
    return false;
  }

  return true;
}

/**
 * Read n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to read.
 * @return True if successful.
 */
static bool ReadBytes(const int sk, char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    if (!SetReadTimeout(sk))
    {
      return false;
    }

    int ret = recv(sk, ptr, ptr - buf + n, 0);
    if (ret <= 0)
    {
      //LOG(ERROR) << "Unable to receive on socket";
      return false;
    }

    ptr += ret;
  }

  return true;
}

/**
 * Write n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to write.
 * @return True if successful.
 */
static bool WriteBytes(const int sk, const char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    int ret = send(sk, ptr, n - (ptr - buf), 0);
    if (ret <= 0)
    {
      printf("Unable to send on socket\n");
      return false;
    }

    ptr += ret;
  }

  return true;
}

bool read_kyber_public_key(const int socket_fd, const uint8_t *public_key, size_t key_length) {
    // Cast the uint8_t array to const char* and send
    return ReadBytes(socket_fd, (const char *)public_key, key_length);
}

bool send_kyber_ciphertext(const int socket_fd, uint8_t *ct, size_t ct_length) {
    // Cast the uint8_t array to char* and read into it
    return WriteBytes(socket_fd, (char *)ct, ct_length);
}

static void OnClient(const int sk)
{
  int size = 8192, i;
  char buf[size];
  int messageSize;
  uint8_t aes_key[PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES];
  uint8_t pk[PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES];
  uint8_t ct[PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES];

  printf("Reading kyber public key\n");

  if (!ReadBytes(sk, &messageSize, sizeof(messageSize)))
  {
    printf("Unable to read response message size\n");
    return;
  }

  printf("message size: %i\n", messageSize);

  if (!read_kyber_public_key(sk, pk, messageSize))
  {
    printf("Unable to read Kyber public key\n");
    return;
  }

  kyber_encapsulate(ct, aes_key, pk);

  messageSize = PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES;

  printf("Sending ciphertext\n");
  WriteBytes(sk, &messageSize, sizeof(messageSize));
  send_kyber_ciphertext(sk, ct, messageSize);

  for (i = 0; i < 16; i++)
    printf("%02x ", (char) aes_key[i]);
  printf("\n");

  expanded = (AES_KEY *)malloc(sizeof(AES_KEY));
  AES_set_encrypt_key(aes_key, 128, expanded);
  AES_encrypt(secret, buf, expanded);
  WriteBytes(sk, buf, 16);
  free(expanded);
}

/**
 * Run the service.
 *
 * @param conf Configuration.
 */
static void RunService(struct Config *conf)
{
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));

  int sk = socket(AF_INET, SOCK_STREAM, 0);
  if (sk < 0)
  {
    printf("Unable to create server socket\n");
    return;
  }

  printf("listening to port: %i\n", conf->port_);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(conf->port_);
  addr.sin_addr.s_addr = INADDR_ANY;

  socklen_t opt = 1;
  if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
  {
    printf("Unable to set REUSE_ADDR on server socket\n");
    return;
  }

  if (bind(sk, (struct sockaddr *)(&addr), sizeof(addr)) < 0)
  {
    printf("Unable to bind server socket\n");
    return;
  }

  if (listen(sk, 16) < 0)
  {
    printf("Unable to listen on server socket\n");
    return;
  }

  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);
  int client_sk;
  pid_t child;
  int st, ret;

  while (true)
  {
    memset(&client_addr, 0, sizeof(client_addr));

    printf("Ready\n");

    client_sk = accept(sk, (struct sockaddr *)(&client_addr), &addr_len);

    if (client_sk < 0)
    {
      printf("Unable to accept connection\n");
      return;
    }

    printf("new connection\n");

    switch (child = fork())
    {
    case -1:
      printf("Unable to fork client handler\n");
      return;

    case 0:
      OnClient(client_sk);
      exit(0);

    default:
      close(client_sk);
      break;
    }

    do
    {
      ret = waitpid(-1, &st, WNOHANG);
    } while (ret > 0);
  }
}

int main(int argc, char **argv)
{
  struct Config conf;
  conf.port_ = 13000;
  parseOpt(argc, argv, &conf);
  RunService(&conf);
  return 0;
}
