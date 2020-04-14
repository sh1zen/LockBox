#ifndef LOCKBOX_SUPPORT_BASE64_H
#define LOCKBOX_SUPPORT_BASE64_H

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;

char* base64_encode(const uint8_t* data, size_t len);

uint8_t* base64_decode(const char* s, size_t in_len, size_t* out_len);

#endif //LOCKBOX_SUPPORT_BASE64_H
