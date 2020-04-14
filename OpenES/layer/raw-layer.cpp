#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <OpenES/support/oes-exception.h>
#include "converter.h"
#include "raw-layer.h"

m_block mBlock_rotr(m_block seed, size_t i) {
    if (i > OES_MEM_SIZE) i &= (OES_MEM_SIZE - 1);

    return (i ? (seed >> i) | (seed << (OES_MEM_SIZE - i)) : seed);
}

m_block mBlock_rotl(m_block seed, size_t i) {
    if (i > OES_MEM_SIZE) i &= (OES_MEM_SIZE - 1);

    return (i ? (seed << i) | (seed >> (OES_MEM_SIZE - i)) : seed);
}

void mBlock_rotr_vec(m_block *block, size_t blockLen, size_t i) {
    if (i == 0 || blockLen == 0) return;

    i %= blockLen; // Modulo corretto invece di bitwise AND
    if (i == 0) return;

    m_block *right = mBlock_clone(nullptr, &(block[blockLen - i]), i);
    m_block *left = mBlock_clone(nullptr, &(block[0]), blockLen - i);

    mBlock_clone(&(block[0]), right, i);
    mBlock_clone(&(block[i]), left, blockLen - i);

    free(right);
    free(left);
}

void mBlock_rotl_vec(m_block *block, size_t blockLen, size_t i) {
    if (i == 0 || blockLen == 0) return;

    i %= blockLen; // Modulo corretto invece di bitwise AND
    if (i == 0) return;

    m_block *right = mBlock_clone(nullptr, &(block[i]), blockLen - i);
    m_block *left = mBlock_clone(nullptr, &(block[0]), i);

    mBlock_clone(&(block[0]), right, blockLen - i);
    mBlock_clone(&(block[blockLen - i]), left, i);

    free(right);
    free(left);
}

m_block *mBlock_padding_einer(const m_block *src, size_t len, size_t outLen, m_block pad) {
    auto padded = static_cast<m_block *>(malloc(outLen * sizeof(m_block)));

    if (!padded) {
        return nullptr; // Controllo allocazione memoria
    }

    memcpy(padded, src, len * sizeof(m_block));

    if (outLen > len) {
        for (size_t i = len; i < outLen - 1; i++) {
            // Correzione: -1 per evitare sovrascrivere l'ultima posizione
            padded[i] = pad;
        }

        padded[outLen - 1] = len;
    }

    return padded;
}

uint32_t mBlock_get_padding_einer(const m_block *block, size_t len, bool inner, m_block pad) {
    if (!block || len == 0) {
        // Controllo validità parametri
        return 0;
    }

    size_t padding = 0;

    if (inner) {
        std::pair<uint8_t *, size_t> converted = toByte_raw(&(block[len - 1]), 1);

        size_t w_len = converted.second;
        uint8_t *w = converted.first;

        if (w && w_len > 0) {
            padding = w[w_len - 1];

            for (size_t i = 1; i < padding; i++) {
                if (w[w_len - 1 - i] != pad) {
                    free(converted.first);
                    throw OESException("OES exception:: invalid padding", OES_EXCEPTION_INV_PAD);
                }
            }
        }
        free(converted.first);
    } else {
        if (block[len - 1] < len) {
            padding = len - block[len - 1];

            for (size_t i = 2; i <= padding; i++) {
                if (block[len - i] != pad) {
                    padding = 0;
                    break;
                }
            }
        }
    }

    return padding;
}


void mBlock_xor(m_block *a, const m_block *b, size_t len, bool alternate) {
    for (size_t i = 0; i < len; i++) {
        if (!alternate || i % 2 == 0) {
            a[i] ^= b[i];
        }
    }
}

void mBlock_toggleBit(m_block *block, size_t pos, int bitN) {
    block[pos] ^= static_cast<m_block>(0x00000001) << bitN; // Cast esplicito
}

void mBlock_dump(const m_block *data, size_t dataLen, bool printable) {
    std::pair<uint8_t *, size_t> converted = toByte_raw(data, dataLen);

    puts("\n========= mBlock dump ===========");

    for (size_t i = 0; i < converted.second; i++) {
        if (i != 0 && i % OES_BYTES_X_BLOCK == 0) {
            printf("|");
        }
        printf("%02x", converted.first[i]);
    }

    if (printable) {
        puts("");

        for (size_t i = 0; i < converted.second; i++) {
            printf("%c", converted.first[i]);
        }
    }

    free(converted.first);

    puts("");
}
