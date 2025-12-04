#include <string>
#include <cstring>

#include "base64.h"

static constexpr char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline bool is_base64(unsigned char c) {
    return std::isalnum(c) || (c == '+') || (c == '/');
}

inline int strchrpos(char e) {
    const char *pos = strchr(base64_chars, e);
    if (!pos) return -1;
    return static_cast<int>(pos - base64_chars);
}

// -------------------- Encode --------------------
std::pair<char *, size_t> base64_encode(const uint8_t *data, size_t len) {
    if (!data || len == 0) return {nullptr, 0};

    size_t encoded_len = ((len + 2) / 3) * 4;
    auto *ret = static_cast<char *>(malloc(encoded_len));
    if (!ret) return {nullptr, 0};

    size_t out_pos = 0;
    size_t i = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];

    for (size_t in_pos = 0; in_pos < len; ++in_pos) {
        char_array_3[i++] = data[in_pos];

        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (size_t j = 0; j < 4; j++) {
                ret[out_pos++] = base64_chars[char_array_4[j]];
            }
            i = 0;
        }
    }

    // Gestione dei byte rimanenti
    if (i > 0) {
        for (size_t j = i; j < 3; j++) {
            char_array_3[j] = 0;
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (size_t j = 0; j < i + 1; j++) {
            ret[out_pos++] = base64_chars[char_array_4[j]];
        }

        while (i++ < 3) {
            ret[out_pos++] = '=';
        }
    }

    return {ret, out_pos};
}

// -------------------- Decode --------------------
std::pair<uint8_t *, size_t> base64_decode(const char *s, size_t in_len) {
    if (!s || in_len == 0) {
        return {nullptr, 0};
    }

    // Rimuovi padding e whitespace dalla lunghezza effettiva
    size_t effective_len = in_len;
    while (effective_len > 0 && (s[effective_len - 1] == '=' || std::isspace(s[effective_len - 1]))) {
        effective_len--;
    }

    // Calcola la dimensione massima dell'output
    size_t max_outLen = ((in_len * 3) / 4) + 3;
    auto *ret = static_cast<uint8_t *>(malloc(max_outLen));
    if (!ret) {
        return {nullptr, 0};
    }

    size_t out_pos = 0;
    size_t in_pos = 0;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    // Processa l'input in chunk di 4 caratteri
    while (in_pos < in_len) {
        // Salta whitespace
        while (in_pos < in_len && std::isspace(s[in_pos])) {
            in_pos++;
        }

        if (in_pos >= in_len) break;

        // Fermati al padding
        if (s[in_pos] == '=') break;

        // Verifica che sia un carattere base64 valido
        if (!is_base64(s[in_pos])) {
            free(ret);
            return {nullptr, 0};
        }

        char_array_4[i++] = s[in_pos++];

        if (i == 4) {
            // Converti i caratteri Base64 in indici
            for (int j = 0; j < 4; j++) {
                int idx = strchrpos(static_cast<char>(char_array_4[j]));
                if (idx < 0) {
                    free(ret);
                    return {nullptr, 0};
                }
                char_array_4[j] = static_cast<unsigned char>(idx);
            }

            // Converti 4 caratteri Base64 in 3 byte
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (int j = 0; j < 3; j++) {
                ret[out_pos++] = char_array_3[j];
            }
            i = 0;
        }
    }

    // Gestione dei caratteri rimanenti (con padding)
    if (i > 0) {
        // Riempi con zeri i caratteri mancanti
        for (int j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }

        // Converti gli indici
        for (int j = 0; j < i; j++) {
            int idx = strchrpos(static_cast<char>(char_array_4[j]));
            if (idx < 0) {
                free(ret);
                return {nullptr, 0};
            }
            char_array_4[j] = static_cast<unsigned char>(idx);
        }

        // Decodifica i byte
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        // Calcola quanti byte sono validi
        // i = numero di caratteri base64 validi (1, 2 o 3)
        // 2 caratteri -> 1 byte, 3 caratteri -> 2 byte, 4 caratteri -> 3 byte
        size_t num_valid_bytes = i - 1;

        for (size_t j = 0; j < num_valid_bytes; j++) {
            ret[out_pos++] = char_array_3[j];
        }
    }

    return {ret, out_pos};
}

// -------------------- Utility --------------------

// Dimensione codificata (include null terminator)
size_t base64_encoded_size(size_t len) {
    return ((len + 2) / 3) * 4 + 1;
}

// Dimensione decodificata da stringa Base64
size_t base64_decoded_size(const char *s, size_t len) {
    if (!s) return 0;
    if (len == 0) len = std::strlen(s);
    if (len == 0) return 0;

    size_t padding = 0;
    if (len >= 1 && s[len - 1] == '=') padding++;
    if (len >= 2 && s[len - 2] == '=') padding++;

    return (len / 4) * 3 - padding;
}
