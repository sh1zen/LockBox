#include "utility.h"
#include "md5.h"
#include "mman.h"
#include "crypto.h"

#define _DEBUG_ 0

char *make_hash(const char *_key, int len) {

    uint8_t *h_md5 = md5(reinterpret_cast<const uint8_t *>(_key), len);

#if _DEBUG_
    for (int j = 0; j < 16; j++)
        printf("%u ", h_md5[j]);

    puts("");
    puts("");
#endif // _DEBUG_

    auto *hash = (uint8_t *) calloc(CRYPTO_HASH_DIM, sizeof(uint8_t));

    // expanse without linear correlation and alter values
    for (int i = 0; i < CRYPTO_HASH_DIM; i++) {

        hash[(i + 6) % CRYPTO_HASH_DIM] ^= h_md5[(hash[i] ^ h_md5[i % 16]) % 16];

        hash[i] ^= ~(h_md5[(i + 1) % 16] % 128);
    }

    for (int i = 0; i < CRYPTO_HASH_DIM; i++)
        hash[i] = hash[i] % 128;

#if _DEBUG_
    for (int j = 0; j < CRYPTO_HASH_DIM; j++)
        printf("%d ", hash[j]);

    puts("");
    puts("");
#endif // _DEBUG_

    free(h_md5);

    return reinterpret_cast<char *>(hash);
}

int encript(char *data, const char *h_md5, off_t data_size) {

    for (off_t i = 0; i < data_size; i++) {
        ROTLEFT(data[i], h_md5[(i << 1) % CRYPTO_HASH_DIM] % 4);
        data[i] = data[i] ^ h_md5[i % CRYPTO_HASH_DIM];
    }

    return 1;
}


int decript(char *data, const char *h_md5, off_t data_size) {

    for (off_t i = 0; i < data_size; i++) {
        data[i] = data[i] ^ h_md5[i % CRYPTO_HASH_DIM];
        ROTRIGHT(data[i], h_md5[(i << 1) % CRYPTO_HASH_DIM] % 4);
    }

    return 1;
}


char *mem_encrypt(char *src, size_t length, char *cipher) {

    encript(src, cipher, length);

    msync(src, length, MS_SYNC);

    return src;
}

u_int64 hash_check(const char *hash)
{
    u_int test = 0;

    for(int j=0; j<CRYPTO_HASH_DIM; j+=2)
        test ^= hash[j];

    return test;
}
