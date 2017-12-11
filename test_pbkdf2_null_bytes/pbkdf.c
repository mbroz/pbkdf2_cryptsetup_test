/*
 * Example: PBKDF2-SHA256 and null bytes
 */
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main(int argc, char *argv[])
{
	const char *password;
	unsigned char salt[32], key[64];
	unsigned long iterations;
	int i;

        OpenSSL_add_all_algorithms();
        printf("OpenSSL (%s):\n", SSLeay_version(SSLEAY_VERSION));

	password = "\xf4\x97\x87\x89\xd5\x2c\x6b\xda"
		   "\xd5\x43\x47\x36\xda\x00\x00\x00";
	RAND_bytes(salt, sizeof(salt));
	iterations = 1000;

	for (i = 12; i <= 16; i++) {
		if (!PKCS5_PBKDF2_HMAC(password, i, salt, sizeof(salt),
			iterations, EVP_sha256(), sizeof(key), key))
			return 2;

		printf("Derived key, pwd length %i\n", i);
		BIO_dump_fp(stdout, (const char *)key, sizeof(key));
	}

	return 0;
}
