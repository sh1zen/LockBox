#pragma once

#include <cstdint>
#include <intrin.h>

struct __uint128_t_msvc {
    uint64_t low;
    uint64_t high;

    constexpr __uint128_t_msvc() : low(0), high(0) {}
    constexpr __uint128_t_msvc(uint64_t l) : low(l), high(0) {}
    constexpr __uint128_t_msvc(uint32_t l) : low(l), high(0) {}
    constexpr __uint128_t_msvc(unsigned long l) : low(l), high(0) {}
    constexpr __uint128_t_msvc(int l) : low(static_cast<uint64_t>(l)), high(l < 0 ? 0xFFFFFFFFFFFFFFFFull : 0) {}
    constexpr __uint128_t_msvc(uint64_t l, uint64_t h) : low(l), high(h) {}

    constexpr __uint128_t_msvc& operator|=(const __uint128_t_msvc& other) {
        low |= other.low;
        high |= other.high;
        return *this;
    }
    constexpr __uint128_t_msvc& operator^=(const __uint128_t_msvc& other) {
        low ^= other.low;
        high ^= other.high;
        return *this;
    }
    constexpr __uint128_t_msvc& operator&=(const __uint128_t_msvc& other) {
        low &= other.low;
        high &= other.high;
        return *this;
    }
    constexpr __uint128_t_msvc& operator++() {
        if (++low == 0) ++high;
        return *this;
    }
    constexpr __uint128_t_msvc operator++(int) {
        __uint128_t_msvc tmp = *this;
        ++(*this);
        return tmp;
    }
    constexpr __uint128_t_msvc& operator--() {
        if (low-- == 0) --high;
        return *this;
    }
    constexpr __uint128_t_msvc operator--(int) {
        __uint128_t_msvc tmp = *this;
        --(*this);
        return tmp;
    }
    constexpr __uint128_t_msvc& operator+=(const __uint128_t_msvc& other) {
        uint64_t old_low = low;
        low += other.low;
        high += other.high + (low < old_low ? 1 : 0);
        return *this;
    }
    constexpr __uint128_t_msvc& operator-=(const __uint128_t_msvc& other) {
        uint64_t old_low = low;
        low -= other.low;
        high -= other.high + (low > old_low ? 1 : 0);
        return *this;
    }
    constexpr __uint128_t_msvc& operator*=(const __uint128_t_msvc& other) {
        if consteval {
            uint64_t a = low, b = high, c = other.low, d = other.high;
            uint64_t a_low = a & 0xFFFFFFFF, a_high = a >> 32;
            uint64_t c_low = c & 0xFFFFFFFF, c_high = c >> 32;

            uint64_t low_low = a_low * c_low;
            uint64_t m1 = a_low * c_high, m2 = a_high * c_low, r = low_low >> 32;
            uint64_t m = m1 + m2;
            uint64_t c1 = (m < m1) ? 1 : 0;
            uint64_t mf = m + r;
            uint64_t c2 = (mf < m) ? 1 : 0;

            low = (low_low & 0xFFFFFFFF) | (mf << 32);
            high = a_high * c_high + (mf >> 32) + ((c1 + c2) << 32) + a * d + b * c;
        } else {
            uint64_t a = low, b = high, c = other.low, d = other.high;
            uint64_t h_part;
            uint64_t l_part = _umul128(a, c, &h_part);
            low = l_part;
            high = h_part + a * d + b * c;
        }
        return *this;
    }
    constexpr __uint128_t_msvc operator<<(unsigned int shift) const {
        if (shift == 0) return *this;
        if (shift >= 128) return {0, 0};
        if (shift >= 64) return {0, low << (shift - 64)};
        return {low << shift, (high << shift) | (low >> (64 - shift))};
    }
    constexpr __uint128_t_msvc operator>>(unsigned int shift) const {
        if (shift == 0) return *this;
        if (shift >= 128) return {0, 0};
        if (shift >= 64) return {high >> (shift - 64), 0};
        return {(low >> shift) | (high << (64 - shift)), high >> shift};
    }
    constexpr __uint128_t_msvc& operator<<=(unsigned int shift) {
        *this = *this << shift;
        return *this;
    }
    constexpr __uint128_t_msvc& operator>>=(unsigned int shift) {
        *this = *this >> shift;
        return *this;
    }
    constexpr __uint128_t_msvc operator|(const __uint128_t_msvc& other) const {
        return {low | other.low, high | other.high};
    }
    constexpr __uint128_t_msvc operator^(const __uint128_t_msvc& other) const {
        return {low ^ other.low, high ^ other.high};
    }
    constexpr __uint128_t_msvc operator&(const __uint128_t_msvc& other) const {
        return {low & other.low, high & other.high};
    }
    constexpr __uint128_t_msvc operator+(const __uint128_t_msvc& other) const {
        __uint128_t_msvc res = *this;
        res += other;
        return res;
    }
    constexpr __uint128_t_msvc operator-(const __uint128_t_msvc& other) const {
        __uint128_t_msvc res = *this;
        res -= other;
        return res;
    }
    constexpr __uint128_t_msvc operator*(const __uint128_t_msvc& other) const {
        __uint128_t_msvc res = *this;
        res *= other;
        return res;
    }
    constexpr explicit operator uint8_t() const { return static_cast<uint8_t>(low); }
    constexpr explicit operator uint64_t() const { return low; }
    constexpr explicit operator uint32_t() const { return static_cast<uint32_t>(low); }
    constexpr explicit operator uint16_t() const { return static_cast<uint16_t>(low); }
    constexpr explicit operator unsigned long() const { return static_cast<unsigned long>(low); }

    constexpr __uint128_t_msvc operator|(uint64_t other) const {
        return {low | other, high};
    }
    constexpr __uint128_t_msvc operator^(uint64_t other) const {
        return {low ^ other, high};
    }
    constexpr __uint128_t_msvc operator&(uint64_t other) const {
        return {low & other, 0};
    }
    constexpr __uint128_t_msvc operator+(uint64_t other) const {
        uint64_t old_low = low;
        uint64_t new_low = low + other;
        return {new_low, high + (new_low < old_low ? 1 : 0)};
    }
    constexpr __uint128_t_msvc operator-(uint64_t other) const {
        uint64_t old_low = low;
        uint64_t new_low = low - other;
        return {new_low, high - (new_low > old_low ? 1 : 0)};
    }
    constexpr __uint128_t_msvc& operator|=(uint64_t other) {
        low |= other;
        return *this;
    }
    constexpr __uint128_t_msvc& operator^=(uint64_t other) {
        low ^= other;
        return *this;
    }
    constexpr __uint128_t_msvc& operator&=(uint64_t other) {
        low &= other;
        high = 0;
        return *this;
    }
    constexpr __uint128_t_msvc& operator+=(uint64_t other) {
        uint64_t old_low = low;
        low += other;
        if (low < old_low) high++;
        return *this;
    }
    constexpr __uint128_t_msvc& operator-=(uint64_t other) {
        uint64_t old_low = low;
        low -= other;
        if (low > old_low) high--;
        return *this;
    }
    constexpr __uint128_t_msvc& operator*=(uint64_t other) {
        if consteval {
            uint64_t a = low, b = high;
            uint64_t a_low = a & 0xFFFFFFFF, a_high = a >> 32;
            uint64_t c_low = other & 0xFFFFFFFF, c_high = other >> 32;

            uint64_t low_low = a_low * c_low;
            uint64_t m1 = a_low * c_high, m2 = a_high * c_low, r = low_low >> 32;
            uint64_t m = m1 + m2;
            uint64_t c1 = (m < m1) ? 1 : 0;
            uint64_t mf = m + r;
            uint64_t c2 = (mf < m) ? 1 : 0;

            low = (low_low & 0xFFFFFFFF) | (mf << 32);
            high = a_high * c_high + (mf >> 32) + ((c1 + c2) << 32) + b * other;
        } else {
            uint64_t h_part;
            uint64_t l_part = _umul128(low, other, &h_part);
            low = l_part;
            high = h_part + high * other;
        }
        return *this;
    }
    constexpr __uint128_t_msvc operator*(uint64_t other) const {
        __uint128_t_msvc res = *this;
        res *= other;
        return res;
    }
    constexpr __uint128_t_msvc operator-() const {
        return ~(*this) + 1u;
    }
    constexpr bool operator==(const __uint128_t_msvc& other) const {
        return low == other.low && high == other.high;
    }
    constexpr bool operator!=(const __uint128_t_msvc& other) const {
        return low != other.low || high != other.high;
    }
    constexpr bool operator==(uint64_t other) const {
        return high == 0 && low == other;
    }
    constexpr bool operator!=(uint64_t other) const {
        return high != 0 || low != other;
    }
    friend constexpr bool operator==(uint64_t lhs, const __uint128_t_msvc& rhs) {
        return rhs == lhs;
    }
    friend constexpr bool operator!=(uint64_t lhs, const __uint128_t_msvc& rhs) {
        return rhs != lhs;
    }
    constexpr bool operator<(const __uint128_t_msvc& other) const {
        return high < other.high || (high == other.high && low < other.low);
    }
    constexpr bool operator>(const __uint128_t_msvc& other) const {
        return other < *this;
    }
    constexpr bool operator<=(const __uint128_t_msvc& other) const {
        return !(*this > other);
    }
    constexpr bool operator>=(const __uint128_t_msvc& other) const {
        return !(*this < other);
    }
    constexpr explicit operator bool() const {
        return low != 0 || high != 0;
    }
    constexpr __uint128_t_msvc operator~() const {
        return {~low, ~high};
    }
    friend constexpr __uint128_t_msvc operator|(uint64_t lhs, const __uint128_t_msvc& rhs) {
        return __uint128_t_msvc(lhs) | rhs;
    }
    friend constexpr __uint128_t_msvc operator^(uint64_t lhs, const __uint128_t_msvc& rhs) {
        return __uint128_t_msvc(lhs) ^ rhs;
    }
    friend constexpr __uint128_t_msvc operator&(uint64_t lhs, const __uint128_t_msvc& rhs) {
        return __uint128_t_msvc(lhs) & rhs;
    }
    friend constexpr __uint128_t_msvc operator+(uint64_t lhs, const __uint128_t_msvc& rhs) {
        return __uint128_t_msvc(lhs) + rhs;
    }
    friend constexpr __uint128_t_msvc operator-(uint64_t lhs, const __uint128_t_msvc& rhs) {
        return __uint128_t_msvc(lhs) - rhs;
    }
    friend constexpr __uint128_t_msvc operator*(uint64_t lhs, const __uint128_t_msvc& rhs) {
        return __uint128_t_msvc(lhs) * rhs;
    }
};

#define __uint128_t __uint128_t_msvc
