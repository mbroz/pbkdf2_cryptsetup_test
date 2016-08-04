ARGON2_DIR=phc-winner-argon2

CPPFLAGS=-DGCRYPT_REQ_VERSION=\"1.5.0\" -I backend -I $(ARGON2_DIR)/include
LDLIBS=-lpthread $(ARGON2_DIR)/libargon2.a
CFLAGS=-O3 -g

all: tst_ssl tst_gcrypt

tst_ssl: $(ARGON2_DIR)/libargon2.a test.o pbkdf_check.o pbkdf2_vectors.o backend/argon2_generic.o backend/crypto_openssl.o
	$(CC) -o $@ $^ -lcrypto -lssl $(LDLIBS)

tst_gcrypt: $(ARGON2_DIR)/libargon2.a test.o pbkdf_check.o pbkdf2_vectors.o backend/argon2_generic.o backend/crypto_gcrypt.o
	$(CC) -o $@ $^ -lgcrypt $(LDLIBS)

$(ARGON2_DIR)/libargon2.a:
	$(MAKE) -C $(ARGON2_DIR)

clean:
	$(MAKE) -C $(ARGON2_DIR) clean
	rm -f *.o backend/*.o *~ core tst_ssl tst_gcrypt

.PHONY: clean
