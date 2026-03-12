#include "raw-layer.h"

#include <OpenES/support/oes-exception.h>
#include "m_block.h"

namespace mBlock {
    /**
     * Extract a single byte from m_block at given position
     *
     * @param block m_block to extract from
     * @param pos Byte position (0 = LSB)
     * @return Extracted byte
     */
    uint8_t getByte(m_block block, uint8_t pos) {
        if (pos >= OES_BYTES_X_BLOCK) {
            return 0;
        }
        return static_cast<uint8_t>((block >> (pos * 8)) & 0xFF);
    }

    /**
     * Convert m_block to byte array (raw, no padding removal)
     *
     * @param block Input m_block array
     * @return Pair of (byte array, length)
     */
    std::pair<uint8_t *, size_t> toBytes(m_block block) {
        if (!block) {
            return std::make_pair(nullptr, 0);
        }

        auto *bytes = new uint8_t[OES_BYTES_X_BLOCK];

        for (size_t j = 0; j < OES_BYTES_X_BLOCK; j++) {
            bytes[j] = static_cast<uint8_t>((block >> (8 * (OES_BYTES_X_BLOCK - 1 - j))) & 0xFF);
        }

        return std::make_pair(bytes, OES_BYTES_X_BLOCK);
    }


    void reverse_range(m_block *a, m_block *b) {
        while (a < b) {
            m_block tmp = *a;
            *a++ = *--b;
            *b = tmp;
        }
    }

    size_t padding_size(m_block block, m_block pad) {
        // Extract bytes in big-endian order
        auto [bytes, _] = toBytes(block);

        // Last byte indicates padding length
        const size_t padding = bytes[OES_BYTES_X_BLOCK - 1];

        // Verify padding bytes
        for (size_t i = 1; i < padding && i < OES_BYTES_X_BLOCK; i++) {
            if (static_cast<m_block>(bytes[OES_BYTES_X_BLOCK - 1 - i]) != pad) {
                throw OESException("OES exception:: invalid padding", OES_EXCEPTION_INV_PAD);
            }
        }

        return padding;
    }

    template<typename T>
    void dump(T x, const char *label) {
        printf("\n");
        if (label) {
            printf("========= %s dump =========\n", label);
        }

        if (x == 0) {
            putchar('0');
            return;
        }

        if constexpr (sizeof(T) <= 8) {
            // Tipi fino a 64 bit
            if constexpr (sizeof(T) == 1) printf("%02x", static_cast<unsigned>(x));
            else if constexpr (sizeof(T) == 2) printf("%04x", static_cast<unsigned>(x));
            else if constexpr (sizeof(T) == 4) printf("%08x", static_cast<unsigned>(x));
            else if constexpr (sizeof(T) == 8) printf("%016llx", static_cast<unsigned long long>(x));
        } else {
            // Tipi più grandi (es. __uint128_t)
            using ULL = unsigned long long;
            const int n_parts = sizeof(T) / sizeof(ULL);
            ULL parts[n_parts];

            // Spezzare x in blocchi da 64 bit
            for (int i = 0; i < n_parts; i++) {
                parts[n_parts - 1 - i] = static_cast<ULL>(x & 0xFFFFFFFFFFFFFFFFULL);
                x >>= 64;
            }

            // Stampare i blocchi
            int started = 0;
            for (int i = 0; i < n_parts; i++) {
                if (!started) {
                    if (parts[i] == 0) continue;
                    printf("%llx", parts[i]);
                    started = 1;
                } else {
                    printf("%016llx", parts[i]);
                }
            }
        }

        putchar('\n');
    }

    template void dump<uint8_t>(uint8_t, const char *label);

    template void dump<uint16_t>(uint16_t, const char *label);

    template void dump<uint32_t>(uint32_t, const char *label);

    template void dump<uint64_t>(uint64_t, const char *label);

    template void dump<__uint128_t>(__uint128_t, const char *label);
}
