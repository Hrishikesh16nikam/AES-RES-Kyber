CC=gcc
OPENSSL=../../codes/openssl
INCLUDE=$(OPENSSL)/include/
KYBER=./kyber512
KEXTRAS=$(KYBER)/fips202.c $(KYBER)/randombytes.c

.PHONY: copy_files

all: server.o

server.o: server.c
	$(CC) server.c -w -I$(INCLUDE) -L$(OPENSSL) -o server.o $(OPENSSL)/libcrypto.a -ldl -lpthread

server_kyber.o: server_kyber.c
	$(CC) server_kyber.c -w -I $(INCLUDE) -L$(OPENSSL) -L$(KYBER) -o server_kyber.o $(OPENSSL)/libcrypto.a $(KYBER)/libkyber512_clean.a $(KEXTRAS) -ldl -lkyber512_clean -lpthread

clean:
	rm -f *.o
	make -C $(KYBER) clean
