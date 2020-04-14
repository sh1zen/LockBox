#include <string>
#include <cstring>
#include <cstdlib>

#include <OpenES/support/support.h>
#include "base64.h"

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Check if character is valid Base64
 */
static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

/**
 * Find position of character in Base64 alphabet
 */
static inline int64_t strchrpos(char e) {
    const char* pos = strchr(base64_chars, e);
    if (!pos) {
        return -1;
    }
    return static_cast<int64_t>(pos - base64_chars);
}

/**
 * Encode binary data to Base64 string
 *
 * @param data Input binary data
 * @param len Length of input data
 * @return Base64-encoded null-terminated string (caller must free)
 */
char* base64_encode(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return nullptr;
    }

    // Calculate output length: ((len + 2) / 3) * 4 + 1 for null terminator
    size_t outLen = (((len + 2) / 3) << 2) + 1;

    auto ret = static_cast<char*>(malloc(outLen * sizeof(char)));
    if (!ret) {
        return nullptr;
    }

    size_t pos = 0;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    const uint8_t* data_ptr = data;
    size_t remaining = len;

    // Process input in 3-byte chunks
    while (remaining > 0) {
        char_array_3[i++] = *(data_ptr++);
        remaining--;

        if (i == 3) {
            // Convert 3 bytes to 4 Base64 characters
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                ret[pos++] = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    // Handle remaining bytes (1 or 2)
    if (i > 0) {
        // Zero-pad remaining bytes
        for (int j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (int j = 0; j < i + 1; j++) {
            ret[pos++] = base64_chars[char_array_4[j]];
        }

        // Add padding
        while (i++ < 3) {
            ret[pos++] = '=';
        }
    }

    ret[pos] = '\0';

    return ret;
}

/**
 * Decode Base64 string to binary data
 *
 * @param s Base64-encoded string
 * @param in_len Length of input string
 * @param out_len Pointer to store output length (can be NULL)
 * @return Decoded binary data (caller must free)
 */
uint8_t* base64_decode(const char* s, size_t in_len, size_t* out_len) {
    if (!s) {
        if (out_len) *out_len = 0;
        return nullptr;
    }

    if (in_len == 0) {
        in_len = strlen(s);
    }

    if (in_len == 0) {
        if (out_len) *out_len = 0;
        return nullptr;
    }

    // Calculate maximum output length
    size_t max_outLen = ((in_len * 3) >> 2) + 3;

    auto ret = static_cast<uint8_t*>(malloc(max_outLen * sizeof(uint8_t)));
    if (!ret) {
        if (out_len) *out_len = 0;
        return nullptr;
    }

    size_t pos = 0;
    size_t in_pos = 0;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    // Process input in 4-character chunks
    while (in_pos < in_len && s[in_pos] != '=' && is_base64(s[in_pos])) {
        char_array_4[i++] = s[in_pos++];

        if (i == 4) {
            // Convert Base64 characters to indices
            for (i = 0; i < 4; i++) {
                int64_t idx = strchrpos(static_cast<char>(char_array_4[i]));
                if (idx < 0) {
                    // Invalid character found
                    free(ret);
                    if (out_len) *out_len = 0;
                    return nullptr;
                }
                char_array_4[i] = static_cast<unsigned char>(idx);
            }

            // Convert 4 Base64 chars to 3 bytes
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) {
                ret[pos++] = char_array_3[i];
            }
            i = 0;
        }
    }

    // Handle remaining characters (with padding)
    if (i > 0) {
        // Zero-pad remaining positions
        for (int j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }

        // Convert Base64 characters to indices
        for (int j = 0; j < i; j++) {
            int64_t idx = strchrpos(static_cast<char>(char_array_4[j]));
            if (idx < 0) {
                // Invalid character found
                free(ret);
                if (out_len) *out_len = 0;
                return nullptr;
            }
            char_array_4[j] = static_cast<unsigned char>(idx);
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (int j = 0; j < i - 1; j++) {
            ret[pos++] = char_array_3[j];
        }
    }

    // Set actual output length
    if (out_len) {
        *out_len = pos;
    }

    return ret;
}

/**
 * Calculate decoded size from Base64 string
 *
 * @param s Base64-encoded string
 * @param len Length of input string (0 to auto-detect)
 * @return Decoded size in bytes
 */
size_t base64_decoded_size(const char* s, size_t len) {
    if (!s) {
        return 0;
    }

    if (len == 0) {
        len = strlen(s);
    }

    if (len == 0) {
        return 0;
    }

    size_t padding = 0;

    // Count padding characters
    if (len > 0 && s[len - 1] == '=') {
        padding++;
        if (len > 1 && s[len - 2] == '=') {
            padding++;
        }
    }

    // Calculate decoded size: (len / 4) * 3 - padding
    return ((len >> 2) * 3) - padding;
}

/**
 * Calculate encoded size for given binary data length
 *
 * @param len Length of binary data
 * @return Encoded size in bytes (including null terminator)
 */
size_t base64_encoded_size(size_t len) {
    // ((len + 2) / 3) * 4 + 1 for null terminator
    return (((len + 2) / 3) << 2) + 1;
}

/**
 * Validate Base64 string
 *
 * @param s Base64 string to validate
 * @param len Length of string (0 to auto-detect)
 * @return true if valid, false otherwise
 */
bool base64_validate(const char* s, size_t len) {
    if (!s) {
        return false;
    }

    if (len == 0) {
        len = strlen(s);
    }

    if (len == 0 || len % 4 != 0) {
        return false;
    }

    size_t padding = 0;

    // Check characters
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '=') {
            // Padding only allowed at end
            if (i < len - 2) {
                return false;
            }
            padding++;
        } else if (!is_base64(static_cast<unsigned char>(s[i]))) {
            return false;
        }
    }

    // Maximum 2 padding characters
    if (padding > 2) {
        return false;
    }

    return true;
}