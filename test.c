#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include "backend/crypto_backend.h"

int pbkdf2_test_vectors(void);

static void pbkdf_performance(const char *test_hash, size_t key_len)
{
	uint32_t iter;

	crypt_pbkdf_check("pbkdf2", test_hash, "foo", 3, "bar", 3, key_len, &iter);
	printf("PBKDF2 %-9s (%-3u bits key): %10llu iterations/second\n",
	       test_hash, key_len * 8, (long unsigned)iter);
}

static void argon2_performance(size_t key_len, uint32_t mem, uint32_t threads, int iter_msec)
{
	uint32_t iter;

	if (!crypt_argon2_check("foo", 3, "barbarba", 8, key_len, mem, threads, iter_msec, &iter))
		printf("Argon2i mem:%5u, threads:%1u, (%03u bits key): %10llu iterations/second\n",
		       mem, threads, key_len * 8, (long unsigned)iter);
	else
		printf("Argon2 run error.\n");
}

int main (int argc, char *argv[])
{
	struct utsname uts;

	if (crypt_backend_init(NULL)) {
		printf("Cannot initialize crypto backend.");
		return 1;
	}

	if (uname(&uts)) {
		printf("Cannot get uname.");
		return 1;
	}

	printf("System : %s %s %s\n", uts.sysname, uts.release, uts.machine);
	printf("Backend: %s\n", crypt_backend_version());

	if (pbkdf2_test_vectors())
		exit(EXIT_FAILURE);

	pbkdf_performance("sha1", 32);
	pbkdf_performance("sha256", 32);
	pbkdf_performance("sha512", 32);
	pbkdf_performance("ripemd160", 32);
	pbkdf_performance("whirlpool", 32);

	argon2_performance(32, 100, 2, 500);
	argon2_performance(32, 10000, 4, 500);
	return 0;
}
