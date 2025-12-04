
#include <cmath>
#include <ctime>
#include <cstring>

#include "random.h"
#include "oes-exception.h"
#include "support.h"

namespace {
    // Costanti per normalizzazione (constexpr per compile-time)
    constexpr double INV_POW2_64 = 5.421010862427522e-20; // 1/2^64
    constexpr double INV_POW2_53 = 1.1102230246251565e-16; // 1/2^53

    // Rotazione a sinistra (intrinsic-friendly)
    [[nodiscard]] constexpr uint64_t rotl64(uint64_t x, int k) noexcept {
        return (x << k) | (x >> (64 - k));
    }

    // xoshiro256** - eccellente qualità statistica, veloce
    struct Xoshiro256 {
        uint64_t s[4];

        uint64_t next() noexcept {
            const uint64_t result = rotl64(s[1] * 5, 7) * 9;
            const uint64_t t = s[1] << 17;

            s[2] ^= s[0];
            s[3] ^= s[1];
            s[1] ^= s[2];
            s[0] ^= s[3];
            s[2] ^= t;
            s[3] = rotl64(s[3], 45);

            return result;
        }

        void jump() noexcept {
            constexpr uint64_t JUMP[] = {
                0x180ec6d33cfd0aba, 0xd5a61266f0c9392c,
                0xa9582618e03fc9aa, 0x39abdc4529b1661c
            };

            uint64_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
            for (uint64_t jmp: JUMP) {
                for (int b = 0; b < 64; ++b) {
                    if (jmp & (uint64_t(1) << b)) {
                        s0 ^= s[0];
                        s1 ^= s[1];
                        s2 ^= s[2];
                        s3 ^= s[3];
                    }
                    next();
                }
            }
            s[0] = s0;
            s[1] = s1;
            s[2] = s2;
            s[3] = s3;
        }
    };

    // SplitMix64 per seeding
    [[nodiscard]] uint64_t splitmix64(uint64_t &state) noexcept {
        uint64_t z = (state += 0x9e3779b97f4a7c15ull);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        return z ^ (z >> 31);
    }
} // namespace anonimo

// ----------------------------------
// IMPLEMENTAZIONE CLASSE
// ----------------------------------

class OES_RNG::Impl {
public:
    Xoshiro256 rng{};
    uint64_t counter = 0;

    ~Impl() {
        secure_memzero(&rng, sizeof(rng));
        secure_memzero(&counter, sizeof(counter));
    }
};

// ----------------------------------
// COSTRUTTORI / DISTRUTTORE
// ----------------------------------

OES_RNG::OES_RNG() : pimpl(new Impl()) {
    init_secure();
}

OES_RNG::OES_RNG(uint64_t seed) : pimpl(new Impl()) {
    init(seed);
}

OES_RNG::OES_RNG(uint64_t seed_hi, uint64_t seed_lo) : pimpl(new Impl()) {
    init(seed_hi, seed_lo);
}

OES_RNG::~OES_RNG() {
    delete pimpl;
}

OES_RNG::OES_RNG(OES_RNG &&other) noexcept : pimpl(other.pimpl) {
    other.pimpl = nullptr;
}

OES_RNG &OES_RNG::operator=(OES_RNG &&other) noexcept {
    if (this != &other) {
        delete pimpl;
        pimpl = other.pimpl;
        other.pimpl = nullptr;
    }
    return *this;
}

// ----------------------------------
// INIT
// ----------------------------------

void OES_RNG::init(uint64_t seed) {
    uint64_t sm = seed ? seed : 0x853c49e6748fea9bull;
    pimpl->rng.s[0] = splitmix64(sm);
    pimpl->rng.s[1] = splitmix64(sm);
    pimpl->rng.s[2] = splitmix64(sm);
    pimpl->rng.s[3] = splitmix64(sm);
    pimpl->counter = 0;

    // Warm-up
    for (int i = 0; i < 16; ++i)
        pimpl->rng.next();
}

void OES_RNG::init(uint64_t seed_hi, uint64_t seed_lo) {
    uint64_t sm1 = seed_hi ? seed_hi : 0x9e3779b97f4a7c15ull;
    uint64_t sm2 = seed_lo ? seed_lo : 0xd1b54a32d192ed03ull;

    pimpl->rng.s[0] = splitmix64(sm1);
    pimpl->rng.s[1] = splitmix64(sm1);
    pimpl->rng.s[2] = splitmix64(sm2);
    pimpl->rng.s[3] = splitmix64(sm2);
    pimpl->counter = 0;

    for (int i = 0; i < 16; ++i)
        pimpl->rng.next();
}

void OES_RNG::init_secure() {
    uint64_t entropy[4];

    // Fallback: combina tempo + indirizzo
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t t1 = static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
                  static_cast<uint64_t>(ts.tv_nsec);
    clock_gettime(CLOCK_REALTIME, &ts);
    auto t2 = static_cast<uint64_t>(ts.tv_nsec);

    entropy[0] = t1 ^ reinterpret_cast<uint64_t>(this);
    entropy[1] = t2 ^ static_cast<uint64_t>(clock());
    entropy[2] = t1 * 0x9e3779b97f4a7c15ull;
    entropy[3] = t2 * 0xd1b54a32d192ed03ull;


    pimpl->rng.s[0] = entropy[0];
    pimpl->rng.s[1] = entropy[1];
    pimpl->rng.s[2] = entropy[2];
    pimpl->rng.s[3] = entropy[3];
    pimpl->counter = 0;

    secure_memzero(entropy, sizeof(entropy));

    for (int i = 0; i < 16; ++i)
        auto volatile _ = pimpl->rng.next();
}

// ----------------------------------
// GENERAZIONE BASE
// ----------------------------------

uint64_t OES_RNG::next64() noexcept {
    ++pimpl->counter;
    return pimpl->rng.next();
}

void OES_RNG::next128(uint64_t &hi, uint64_t &lo) noexcept {
    lo = next64();
    hi = next64();
}

uint64_t OES_RNG::operator()() noexcept {
    return next64();
}

// ----------------------------------
// RANGE (rejection sampling ottimizzato)
// ----------------------------------

size_t OES_RNG::range(size_t max) noexcept {
    if (max <= 1) return 0;

    // Lemire's nearly divisionless method
    __uint128_t m = static_cast<__uint128_t>(next64()) * max;

    if (auto l = static_cast<uint64_t>(m); l < max) {
        uint64_t t = -max % max;
        while (l < t) {
            m = static_cast<__uint128_t>(next64()) * max;
            l = static_cast<uint64_t>(m);
        }
    }
    return static_cast<size_t>(m >> 64);
}

size_t OES_RNG::range(size_t min, size_t max) noexcept {
    if (min >= max) return min;
    return min + range(max - min);
}

// ----------------------------------
// UNIFORM [0, 1)
// ----------------------------------

double OES_RNG::uniform() noexcept {
    // Usa solo 53 bit (precisione double) - più veloce e corretto
    return static_cast<double>(next64() >> 11) * INV_POW2_53;
}

double OES_RNG::uniform_full() noexcept {
    // Versione a 128 bit per massima entropia
    uint64_t hi = next64();
    uint64_t lo = next64();

    // Combina i 128 bit in un double [0, 1)
    double d = static_cast<double>(hi) * INV_POW2_64;
    d += static_cast<double>(lo >> 11) * INV_POW2_53 * INV_POW2_64;
    return d < 1.0 ? d : 0.9999999999999999;
}

double OES_RNG::uniform(double min, double max) noexcept {
    return min + (max - min) * uniform();
}

// ----------------------------------
// BOOLEAN
// ----------------------------------

bool OES_RNG::boolean(double p) noexcept {
    if (p <= 0.0) return false;
    if (p >= 1.0) return true;
    return uniform() < p;
}

// ----------------------------------
// DISTRIBUZIONI
// ----------------------------------

double OES_RNG::gaussian(double mean, double stddev) noexcept {
    // Box-Muller con cache (genera 2 valori, usa 1)
    double u1;
    do {
        u1 = uniform();
    } while (u1 == 0.0); // Evita log(0)

    double u2 = uniform();
    double z = std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * M_PI * u2);
    return mean + z * stddev;
}

double OES_RNG::exponential(double lambda) noexcept {
    double u;
    do {
        u = uniform();
    } while (u == 0.0);
    return -std::log(u) / lambda;
}

// ----------------------------------
// SHUFFLE (Fisher-Yates ottimizzato)
// ----------------------------------

void OES_RNG::shuffle(void *data, size_t count, size_t elem_size) noexcept {
    if (count < 2 || elem_size == 0) return;

    auto *arr = static_cast<uint8_t *>(data);
    alignas(16) uint8_t tmp[64]; // Stack buffer per elementi piccoli

    const bool use_stack = elem_size <= sizeof(tmp);
    uint8_t *swap_buf = use_stack ? tmp : new uint8_t[elem_size];

    for (size_t i = count - 1; i > 0; --i) {
        size_t j = range(i + 1);
        if (i != j) {
            uint8_t *a = arr + i * elem_size;
            uint8_t *b = arr + j * elem_size;
            std::memcpy(swap_buf, a, elem_size);
            std::memcpy(a, b, elem_size);
            std::memcpy(b, swap_buf, elem_size);
        }
    }

    if (!use_stack) delete[] swap_buf;
}

// ----------------------------------
// FILL
// ----------------------------------

void OES_RNG::fill_bytes(void *buffer, size_t size) noexcept {
    auto *buf = static_cast<uint8_t *>(buffer);
    auto *aligned = reinterpret_cast<uint64_t *>(buf);

    size_t blocks = size / sizeof(uint64_t);
    size_t rem = size % sizeof(uint64_t);

    // Unroll per performance
    size_t i = 0;
    for (; i + 4 <= blocks; i += 4) {
        aligned[i] = next64();
        aligned[i + 1] = next64();
        aligned[i + 2] = next64();
        aligned[i + 3] = next64();
    }
    for (; i < blocks; ++i) {
        aligned[i] = next64();
    }

    if (rem) {
        uint64_t x = next64();
        std::memcpy(buf + blocks * sizeof(uint64_t), &x, rem);
    }
}

void OES_RNG::fill_secure(void *buffer, size_t size) noexcept {
    fill_bytes(buffer, size);
}

// ----------------------------------
// CHOICE
// ----------------------------------

size_t OES_RNG::choice_index(size_t count) noexcept {
    return range(count);
}

std::vector<size_t> OES_RNG::sample_indices(size_t n, size_t k) {
    if (k > n) {
        throw OESException("Sample size exceeds population");
    }

    std::vector<size_t> result;
    result.reserve(k);

    if (k == 0) return result;

    // Floyd's algorithm: O(k) per k << n
    if (k <= n / 4) {
        std::vector<bool> selected(n, false);
        for (size_t i = n - k; i < n; ++i) {
            size_t j = range(i + 1);
            if (selected[j]) {
                result.push_back(i);
                selected[i] = true;
            } else {
                result.push_back(j);
                selected[j] = true;
            }
        }
    } else {
        // Per k grande: shuffle parziale
        std::vector<size_t> indices(n);
        for (size_t i = 0; i < n; ++i) indices[i] = i;

        for (size_t i = 0; i < k; ++i) {
            size_t j = range(i, n);
            std::swap(indices[i], indices[j]);
        }
        result.assign(indices.begin(), indices.begin() + k);
    }

    return result;
}

// ----------------------------------
// UUID (RFC 4122 v4)
// ----------------------------------

void OES_RNG::uuid(uint64_t &hi, uint64_t &lo) noexcept {
    hi = next64();
    lo = next64();

    // Version 4
    hi = (hi & 0xFFFFFFFFFFFF0FFFull) | 0x0000000000004000ull;
    // Variant 10xx
    lo = (lo & 0x3FFFFFFFFFFFFFFFull) | 0x8000000000000000ull;
}

void OES_RNG::uuid_bytes(uint8_t out[16]) noexcept {
    uint64_t hi, lo;
    uuid(hi, lo);

    // Big-endian per UUID standard
    for (int i = 7; i >= 0; --i) {
        out[7 - i] = static_cast<uint8_t>(hi >> (i * 8));
        out[15 - i] = static_cast<uint8_t>(lo >> (i * 8));
    }
}

// ----------------------------------
// STATE
// ----------------------------------

OES_RNG::State OES_RNG::save_state() const noexcept {
    State s;
    std::memcpy(s.data, pimpl->rng.s, sizeof(pimpl->rng.s));
    s.counter = pimpl->counter;
    return s;
}

void OES_RNG::restore_state(const State &s) noexcept {
    std::memcpy(pimpl->rng.s, s.data, sizeof(pimpl->rng.s));
    pimpl->counter = s.counter;
}

uint64_t OES_RNG::get_counter() const noexcept {
    return pimpl->counter;
}

void OES_RNG::jump() noexcept {
    pimpl->rng.jump();
}

// ----------------------------------
// TEST
// ----------------------------------

double OES_RNG::test_uniformity(size_t samples, size_t buckets) {
    std::vector<size_t> c(buckets, 0);

    for (size_t i = 0; i < samples; ++i) {
        c[range(buckets)]++;
    }

    const double e = static_cast<double>(samples) / static_cast<double>(buckets);
    double chi = 0.0;

    for (size_t x: c) {
        double d = static_cast<double>(x) - e;
        chi += (d * d) / e;
    }

    return chi;
}
