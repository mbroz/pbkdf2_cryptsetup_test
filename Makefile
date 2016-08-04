CPPFLAGS=-DGCRYPT_REQ_VERSION=\"1.5.0\" -I backend -I phc-winner-argon2/include
LDLIBS=-lpthread phc-winner-argon2/libargon2.a
CFLAGS=-O3

all: tst_ssl tst_gcrypt

tst_ssl: test.o pbkdf_check.o pbkdf2_vectors.o backend/argon2_generic.o backend/crypto_openssl.o
	$(CC) -o $@ $^ -lcrypto -lssl $(LDLIBS)

tst_gcrypt: test.o pbkdf_check.o pbkdf2_vectors.o backend/argon2_generic.o backend/crypto_gcrypt.o
	$(CC) -o $@ $^ -lgcrypt $(LDLIBS)

clean:
	rm -f *.o backend/*.o *~ core tst_ssl tst_gcrypt

.PHONY: clean
