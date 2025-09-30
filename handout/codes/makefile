CC = gcc
CFLAGS = -Wno-deprecated-declarations
OPENSSL = /root/openssl
KYBER = ../kyber512

all: p1 p3

# -------------------------
# Module 1 (Performance)
# -------------------------
p1: aes_test rsa_test kyber_test benchmark
	@./aes_test
	@./rsa_test
	@./kyber_test
	@./benchmark
	@echo "Generating timing plots..."
	@python3 plot_timings.py

aes_test: aes_test.c timer.c
	@$(CC) $(CFLAGS) aes_test.c timer.c -I$(OPENSSL)/include -L$(OPENSSL) \
	-o aes_test $(OPENSSL)/libcrypto.a -ldl

rsa_test: rsa_test.c timer.c
	@$(CC) $(CFLAGS) rsa_test.c timer.c -I$(OPENSSL)/include -L$(OPENSSL) \
	-o rsa_test $(OPENSSL)/libcrypto.a -ldl

kyber_test: kyber_test.c timer.c
	@$(CC) $(CFLAGS) kyber_test.c timer.c -I$(OPENSSL)/include -I$(KYBER) \
	-L$(OPENSSL) -L$(KYBER) -o kyber_test \
	$(OPENSSL)/libcrypto.a $(KYBER)/libkyber512_clean.a \
	$(KYBER)/fips202.c $(KYBER)/randombytes.c -ldl

benchmark: benchmark.c timer.c
	@$(CC) $(CFLAGS) benchmark.c timer.c -I$(OPENSSL)/include -I$(KYBER) \
	-L$(OPENSSL) -L$(KYBER) -o benchmark \
	$(OPENSSL)/libcrypto.a $(KYBER)/libkyber512_clean.a \
	$(KYBER)/fips202.c $(KYBER)/randombytes.c -ldl


# -------------------------
# Module 2 (Images via CLI)
# -------------------------
p2:
	@echo "Run the OpenSSL CLI commands from lab instructions for ECB/CBC mode."


# -------------------------
# Module 3 (Clients)
# -------------------------
p3: client_rsa client_kyber
	@./client_rsa
	@./client_kyber

client_rsa: client_rsa.c
	@$(CC) $(CFLAGS) client_rsa.c -I$(OPENSSL)/include -L$(OPENSSL) \
	-o client_rsa $(OPENSSL)/libcrypto.a -ldl

client_kyber: client_kyber.c
	@$(CC) $(CFLAGS) client_kyber.c -I$(OPENSSL)/include -I$(KYBER) \
	-L$(OPENSSL) -L$(KYBER) -o client_kyber \
	$(OPENSSL)/libcrypto.a $(KYBER)/libkyber512_clean.a \
	$(KYBER)/fips202.c $(KYBER)/randombytes.c -ldl

# -------------------------
# Clean
# -------------------------
clean:
	@rm -f aes_test rsa_test kyber_test benchmark client_rsa client_kyber *.o *.txt *.png


