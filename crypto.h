#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#define CRYPTO_HASH_DIM 256

#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32-(b))))


char *make_hash(const char *_key, int len);

int encript(char *data, const char *key, off_t data_size);

int decript(char *data, const char *key, off_t data_size);

char *mem_encrypt(char *src, size_t length, char *cipher);

u_int64 hash_check(const char *hash);

#endif
