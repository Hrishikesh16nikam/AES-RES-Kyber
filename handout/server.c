#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>

int padding = RSA_PKCS1_PADDING;
AES_KEY *expanded;

uint8_t secret[16] = {
    0xb2, 0x01, 0x12, 0x93,
    0xe9, 0x55, 0x26, 0xa7,
    0xea, 0x69, 0x3a, 0xcb,
    0xfc, 0x7d, 0x0e, 0x1f};

/**
 * Configuration.
 */
struct Config
{
  uint16_t port_;
};

char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAroyB+A4W/acwRq9gthl0\n"
"jb81nPHQ/s9lZNq0AEUnkWnOK+Rae+JoupsSeUehKYJQJkFYjnBc2aV8gSqxtY+b\n"
"r/XcIRSgk9ULUdELaak1WaYfjVEhyUgiQSXBa/QVsnSLMe4Hn6Mdx9J31y3/TLNp\n"
"AaB3Q37e9nfi3xT8K05govYbgV+j9z0zqJeJhS0D7aRzCc+MYDGlVuLpA0UDtjmA\n"
"KM0xD4e0U845qeUMqq7CdXt5mIiqFr7BL28F7zD9b5tqr407UEhsTESnkP9jfFJM\n"
"+t9+EKVUGmNTJMQPimRFot0ZGaTz4J4Jcnl3y0UhwwNqSVpnrOhAkzV+MhHmNOoc\n"
"wwIDAQAB\n"
                   "-----END PUBLIC KEY-----\n";

char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEAroyB+A4W/acwRq9gthl0jb81nPHQ/s9lZNq0AEUnkWnOK+Ra\n"
"e+JoupsSeUehKYJQJkFYjnBc2aV8gSqxtY+br/XcIRSgk9ULUdELaak1WaYfjVEh\n"
"yUgiQSXBa/QVsnSLMe4Hn6Mdx9J31y3/TLNpAaB3Q37e9nfi3xT8K05govYbgV+j\n"
"9z0zqJeJhS0D7aRzCc+MYDGlVuLpA0UDtjmAKM0xD4e0U845qeUMqq7CdXt5mIiq\n"
"Fr7BL28F7zD9b5tqr407UEhsTESnkP9jfFJM+t9+EKVUGmNTJMQPimRFot0ZGaTz\n"
"4J4Jcnl3y0UhwwNqSVpnrOhAkzV+MhHmNOocwwIDAQABAoIBAC8kO6XnCEaRdPRi\n"
"QVhtH5F45t3wYWWwVc4bUyoPg1Q+ozQvhFCZIXfkkeS3d8tiKotqcqRlrG4Lx8iK\n"
"41wJ4R5w5Hb6vzOuAlSihNaQoJwJxdPA6cMW/ElkDQ0+6u07lKxzgROYVl61dTBk\n"
"d+MbQWzzDcLo7Qbb8iYV4NVBYdAg/axDMfYR7UBkCkwedIW0S62wf/EM1qLptV1L\n"
"dP4HaSXTehPIUqC+IZhAZIDE6cR+okESuRP5sYG1Pu0dOG0+NBaWDGqcbpcArug/\n"
"EpK3IMJ466zZSpK2wHLqsV/ZYWe6/vLEELVDN170T8UPTdaFQAtJn4V3U6hyp3el\n"
"YvprZSECgYEA2ODFJs/10XOs+MTFvd42ZDUs7L49WBuLsYyyGcDS2HfCtW4OzSuU\n"
"cVu9Zl/oAO1zCoTQOCT8plgFfLIExbIFzuel52AE5ZB98EfGI88pG28x0mLHXok7\n"
"xn+E0r/YWtRBPQRGsjjyr04CK0fYeu8ncEZNTqSl8aUw311cljJKDr8CgYEAzgkE\n"
"CeRJXEWszBtHnmZQPltuL2AMX4RYqLI1Y+Q2ea4ydfjLtrf6zfDAUCHLwKSqF/RZ\n"
"l73EG7fI3mwlt0VirbQz4cjpUOFkKhxqrCAIVy9SDt8k1nEkfstidz5xv90umCNw\n"
"1b1dh9CkNhq5Q99Tz6fZvc+jMi4V+kNtP1ny9v0CgYEAjRK4a6S+m74I99DXZ8gR\n"
"zWEhleWxdYyFc7q3ZzUccZ6FUwsCKcd9SbeJHfyop2HNgTwfTUYR6go7l38cx5Qj\n"
"XxEjw7ubs9Ane5LUehqY/LV5zQZf9UiDT31HYudTztFellgfvHJ6ujmeA5U6Zc0G\n"
"9Gtmgg9ruiHgBotuXGzd63UCgYAGhfyNv5+e/0nAUKDM4BpsTwLHFzhtEcio1rOg\n"
"DQq4gY5xc8Yna93SBWxhXSCRYeVMytzHVCfQZNpESJJNIjJEo6782BqjB+/e8XVj\n"
"K8R31jS36dLFw2FPbmsYsW5yj7M49+5Lpio+8ZkxaVkyT/DcY0kenGNjZFgny1i7\n"
"J8LslQKBgHqC07rssivOLWlvESgMRot8ZjkwNmBMrdooa4qWKSvLckVnj/IR2jsc\n"
"rlxOI9gMJXGmqNqoEr9OydF85AOIY4YCgwBUuCuFudskCN0YpwGVYSL4KimB0YUx\n"
"WHptz8Q2L/JzQHZqic1nj2TXrDj9RayR2GolBfEJ+0nFY2wtxwqL\n"
                      "-----END RSA PRIVATE KEY-----\n";

RSA *createRSA(unsigned char *key, int public)
{
  RSA *rsa = NULL;
  BIO *keybio;
  keybio = BIO_new_mem_buf(key, -1);
  if (keybio == NULL)
  {
    printf("Failed to create key BIO");
    return 0;
  }
  if (public)
  {
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
  }
  else
  {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  }
  if (rsa == NULL)
  {
    printf("Failed to create RSA");
  }

  return rsa;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *key,
                   unsigned char *encrypted)
{
  RSA *rsa = createRSA(key, 1);
  int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
  return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
                    unsigned char *decrypted)
{
  RSA *rsa = createRSA(key, 0);
  int result =
      RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
  return result;
}

int private_encrypt(unsigned char *data, int data_len, unsigned char *key,
                    unsigned char *encrypted)
{
  RSA *rsa = createRSA(key, 0);
  int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
  return result;
}

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
                   unsigned char *decrypted)
{
  RSA *rsa = createRSA(key, 1);
  int result =
      RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
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
    printf("unable to set read timeout\n");
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
      //LOG(ERROR) << "unable to receive on socket";
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
      printf("unable to send on socket\n");
      return false;
    }

    ptr += ret;
  }

  return true;
}

static void OnClient(const int sk)
{
  int size = 8192;
  char buf[size];
  int messageSize;

  int publicKeySize = strlen(publicKey);

  printf("sending public keys\n");

  WriteBytes(sk, &publicKeySize, sizeof(publicKeySize));

  WriteBytes(sk, publicKey, publicKeySize);

  if (!ReadBytes(sk, &messageSize, sizeof(messageSize)))
  {
    printf("unable to read response message size\n");
    return;
  }

  printf("message size: %i\n", messageSize);

  if (!ReadBytes(sk, buf, messageSize))
  {
    printf("unable to read encrypted AES key\n");
    return;
  }

  unsigned char key[16];
  int i;
  for (i = 0; i < 16; i++)
    printf("%02x ", key[i]);
  printf("\n");

  i = private_decrypt(buf, messageSize, privateKey, key);
  printf("resutl: %i\n", i);

  for (i = 0; i < 16; i++)
    printf("%02x ", key[i]);
  printf("\n");

  expanded = (AES_KEY *)malloc(sizeof(AES_KEY));

  AES_set_encrypt_key(key, 128, expanded);

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
    printf("unable to create server socket\n");
    return;
  }

  printf("listening to port: %i\n", conf->port_);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(conf->port_);
  addr.sin_addr.s_addr = INADDR_ANY;

  socklen_t opt = 1;
  if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
  {
    printf("unable to set REUSE_ADDR on server socket\n");
    return;
  }

  if (bind(sk, (struct sockaddr *)(&addr), sizeof(addr)) < 0)
  {
    printf("unable to bind server socket\n");
    return;
  }

  if (listen(sk, 16) < 0)
  {
    printf("unable to listen on server socket\n");
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
      printf("unable to accept connection\n");
      return;
    }

    printf("new connection\n");

    switch (child = fork())
    {
    case -1:
      printf("unable to fork client handler\n");
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
  conf.port_ = 12000;
  parseOpt(argc, argv, &conf);
  RunService(&conf);
  return 0;
}
