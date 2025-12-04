#ifndef LOCKBOX_SUPPORT_BASE64_H
#define LOCKBOX_SUPPORT_BASE64_H

typedef unsigned char uint8_t;

std::pair<char *, size_t> base64_encode(const uint8_t *data, size_t len);

std::pair<uint8_t *, size_t> base64_decode(const char *s, size_t in_len);

#endif //LOCKBOX_SUPPORT_BASE64_H
