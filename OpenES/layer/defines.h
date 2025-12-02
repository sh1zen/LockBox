#ifndef LOCKBOX_DEFINES_H
#define LOCKBOX_DEFINES_H

#ifndef OES_NUM_OF_BLOCK
#define OES_NUM_OF_BLOCK 8
#endif

#ifndef OES_LOGIC_BLOCK_SIZE
#define OES_LOGIC_BLOCK_SIZE 32
#endif

#if (OES_LOGIC_BLOCK_SIZE % 8 != 0 || OES_LOGIC_BLOCK_SIZE < 8 || OES_LOGIC_BLOCK_SIZE > 128)
#error "OES_LOGIC_BLOCK_SIZE must be a multpiple of 8"
#endif

#if OES_LOGIC_BLOCK_SIZE <= 16
#define OES_MEM_SIZE 16
#elif OES_LOGIC_BLOCK_SIZE <= 32
#define OES_MEM_SIZE 32
#elif OES_LOGIC_BLOCK_SIZE <= 64
#define OES_MEM_SIZE 64
#elif OES_LOGIC_BLOCK_SIZE <= 128
#define OES_MEM_SIZE 128
#endif

// masking for mem size constants
#if OES_MEM_SIZE == 128
#define MASK_TO_BLOCK_SIZE(high, low) ((((__uint128_t)high) << 64) | low)
#elif OES_MEM_SIZE == 64
#define MASK_TO_BLOCK_SIZE(high, low) (low)
#else
#define MASK_TO_BLOCK_SIZE(high, low) ((low) & ((1ull << OES_MEM_SIZE) - 1))
#endif

#define OES_BYTES_X_BLOCK (OES_MEM_SIZE / 8)
#define OES_HALF_BLOCK_SIZE (OES_MEM_SIZE >= 16 ? OES_MEM_SIZE / 2 : 8)

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef signed long long int64_t;
typedef unsigned long long uint64_t;


#define OES_EXPORT_RAW 1
#define OES_EXPORT_UINT8 2
#define OES_EXPORT_HEX 3
#define OES_EXPORT_CHAR 4
#define OES_EXPORT_BASE64 5

#define OES_EXCEPTION_INV_PAD 5

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

#endif //LOCKBOX_DEFINES_H
