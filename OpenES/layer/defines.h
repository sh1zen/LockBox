#ifndef LOCKBOX_DEFINES_H
#define LOCKBOX_DEFINES_H

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;

// todo update  to  32 se è 32 bit la macchina
typedef uint64_t size_t;


#define OES_EXPORT_RAW 1
#define OES_EXPORT_UINT8 2
#define OES_EXPORT_HEX 3
#define OES_EXPORT_CHAR 4
#define OES_EXPORT_BASE64 5

#define OES_EXCEPTION_INV_PAD 5

#define OES_BLOCK_SIZE 64

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

#endif //LOCKBOX_DEFINES_H
