#ifndef LOCKBOX_DEFINES_H
#define LOCKBOX_DEFINES_H

#ifndef OES_NUM_OF_BLOCK
#define OES_NUM_OF_BLOCK 16
#endif

#ifndef OES_LOGIC_BLOCK_SIZE
#define OES_LOGIC_BLOCK_SIZE 128
#endif

#if OES_NUM_OF_BLOCK % 2 != 0
#error "OES_NUM_OF_BLOCK must be a multpiple of 2"
#endif

#if (OES_LOGIC_BLOCK_SIZE % 8 != 0 || OES_LOGIC_BLOCK_SIZE < 8 || OES_LOGIC_BLOCK_SIZE > 128)
#error "OES_LOGIC_BLOCK_SIZE must be a multpiple of 8"
#endif

#if OES_LOGIC_BLOCK_SIZE <= 8
#define OES_MEM_SIZE 8
#elif OES_LOGIC_BLOCK_SIZE <= 16
#define OES_MEM_SIZE 16
#elif OES_LOGIC_BLOCK_SIZE <= 32
#define OES_MEM_SIZE 32
#elif OES_LOGIC_BLOCK_SIZE <= 64
#define OES_MEM_SIZE 64
#elif OES_LOGIC_BLOCK_SIZE <= 128
#define OES_MEM_SIZE 128
#endif

#define OES_MEM_SIZE_MASK (OES_MEM_SIZE - 1)
#define OES_HALF_MEM_SIZE (OES_MEM_SIZE / 2)
#define OES_HALF_MEM_SIZE_MASK (OES_HALF_MEM_SIZE - 1)


#if OES_MEM_SIZE == 8
#define OES_HALF_BLOCK_MASK 0x0Fu
#elif OES_MEM_SIZE == 16
#define OES_HALF_BLOCK_MASK 0x00FFu
#elif OES_MEM_SIZE == 32
#define OES_HALF_BLOCK_MASK 0x0000FFFFu
#elif OES_MEM_SIZE == 64
#define OES_HALF_BLOCK_MASK 0x00000000FFFFFFFFull
#elif OES_MEM_SIZE == 128
#define OES_HALF_BLOCK_MASK 0xFFFFFFFFFFFFFFFFull
#endif


#define OES_BYTES_X_BLOCK (OES_MEM_SIZE / 8)

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


template<unsigned Bits>
consteval auto mask_to_block_size(uint64_t high, const uint64_t low) {
    static_assert(Bits > 0 && Bits <= 128, "Invalid bit size");

    if constexpr (Bits == 128) {
        return (static_cast<__uint128_t>(high) << 64) | static_cast<__uint128_t>(low);
    } else if constexpr (Bits == 64) {
        return high;
    } else if constexpr (Bits == 32) {
        return static_cast<uint32_t>(high >> 32);
    } else if constexpr (Bits == 16) {
        // solo MSB di high
        return static_cast<uint16_t>(high >> 48);
    } else if constexpr (Bits == 8) {
        // solo MSB di high
        return static_cast<uint8_t>(high >> 56);
    }
}

// masking for mem size constants
#define MASK_TO_BLOCK_SIZE(high, low) mask_to_block_size<OES_MEM_SIZE>(high, low)

// --- Macro generiche di replica sicure con cast corretto ---
#define REPLICATE_16_8(v) ((uint8_t)(v))
#define REPLICATE_16_16(v) ((uint16_t)(v))
#define REPLICATE_16_32(v) ((uint32_t)((uint32_t)(v) | ((uint32_t)(v)<<16)))
#define REPLICATE_16_64(v) ((uint64_t)((uint64_t)(v) | ((uint64_t)(v)<<16) | ((uint64_t)(v)<<32) | ((uint64_t)(v)<<48)))
#define REPLICATE_16_128(v) (((__uint128_t)REPLICATE_16_64(v) << 64) | REPLICATE_16_64(v))

// --- Macro principale senza warning ---
#if OES_MEM_SIZE == 8
#define REPLICATE_BITS(val) REPLICATE_16_8(val)
#elif OES_MEM_SIZE == 16
#define REPLICATE_BITS(val) REPLICATE_16_16(val)
#elif OES_MEM_SIZE == 32
#define REPLICATE_BITS(val) REPLICATE_16_32(val)
#elif OES_MEM_SIZE == 64
#define REPLICATE_BITS(val) REPLICATE_16_64(val)
#elif OES_MEM_SIZE == 128
#define REPLICATE_BITS(val) REPLICATE_16_128(val)
#endif


#endif //LOCKBOX_DEFINES_H
