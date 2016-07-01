CPPFLAGS=-DGCRYPT_REQ_VERSION=\"1.5.0\"
CFLAGS=-O3

#SOURCES=$(wildcard *.c)
#OBJECTS=$(SOURCES:.c=.o)

all: tst_ssl tst_gcrypt

tst_ssl: test.o pbkdf_check.o pbkdf2_vectors.o backend/crypto_openssl.o
	$(CC) -o $@ $^ -lcrypto -lssl $(LDLIBS)

tst_gcrypt: test.o pbkdf_check.o pbkdf2_vectors.o backend/crypto_gcrypt.o
	$(CC) -o $@ $^ -lgcrypt $(LDLIBS)

#$(TARGET): $(OBJECTS)
#	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o backend/*.o *~ core tst_ssl tst_gcrypt

.PHONY: clean
