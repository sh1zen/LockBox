#ifndef RANDOM_H
#define RANDOM_H

#include <cstdint>
#include <vector>

class OES_RNG {
public:
    // Stato serializzabile (256 bit + counter)
    struct State {
        uint64_t data[4];
        uint64_t counter;
    };

    // Costruttori
    OES_RNG();                                    // Init con entropia di sistema
    explicit OES_RNG(uint64_t seed);              // Init deterministico
    OES_RNG(uint64_t seed_hi, uint64_t seed_lo);  // Init con 128 bit

    ~OES_RNG();

    // Move semantics (no copy - stato unico)
    OES_RNG(OES_RNG&& other) noexcept;
    OES_RNG& operator=(OES_RNG&& other) noexcept;
    OES_RNG(const OES_RNG&) = delete;
    OES_RNG& operator=(const OES_RNG&) = delete;

    // Inizializzazione
    void init(uint64_t seed);
    void init(uint64_t seed_hi, uint64_t seed_lo);
    void init_secure();  // Usa entropia crittografica del sistema

    // Generazione base
    [[nodiscard]] uint64_t next64() noexcept;
    void next128(uint64_t& hi, uint64_t& lo) noexcept;
    [[nodiscard]] uint64_t operator()() noexcept;

    // Range [0, max) e [min, max)
    [[nodiscard]] size_t range(size_t max) noexcept;
    [[nodiscard]] size_t range(size_t min, size_t max) noexcept;

    // Uniform [0, 1)
    [[nodiscard]] double uniform() noexcept;       // 53 bit (veloce)
    [[nodiscard]] double uniform_full() noexcept;  // 128 bit (massima precisione)
    [[nodiscard]] double uniform(double min, double max) noexcept;

    // Boolean
    [[nodiscard]] bool boolean(double p = 0.5) noexcept;

    // Distribuzioni
    [[nodiscard]] double gaussian(double mean = 0.0, double stddev = 1.0) noexcept;
    [[nodiscard]] double exponential(double lambda = 1.0) noexcept;

    // Shuffle generico (Fisher-Yates)
    void shuffle(void* data, size_t count, size_t elem_size) noexcept;

    template<typename T>
    void shuffle(std::vector<T>& v) noexcept {
        shuffle(v.data(), v.size(), sizeof(T));
    }

    template<typename T, size_t N>
    void shuffle(T (&arr)[N]) noexcept {
        shuffle(arr, N, sizeof(T));
    }

    // Fill
    void fill_bytes(void* buffer, size_t size) noexcept;
    void fill_secure(void* buffer, size_t size) noexcept;  // Entropia crittografica

    template<typename T>
    void fill(std::vector<T>& v) noexcept {
        fill_bytes(v.data(), v.size() * sizeof(T));
    }

    // Choice (restituisce indice)
    [[nodiscard]] size_t choice_index(size_t count) noexcept;

    template<typename T>
    [[nodiscard]] const T& choice(const std::vector<T>& v) noexcept {
        return v[choice_index(v.size())];
    }

    template<typename T>
    [[nodiscard]] T& choice(std::vector<T>& v) noexcept {
        return v[choice_index(v.size())];
    }

    // Sample (restituisce k indici distinti da [0, n))
    [[nodiscard]] std::vector<size_t> sample_indices(size_t n, size_t k);

    template<typename T>
    [[nodiscard]] std::vector<T> sample(const std::vector<T>& pop, size_t k) {
        auto indices = sample_indices(pop.size(), k);
        std::vector<T> result;
        result.reserve(k);
        for (size_t i : indices) {
            result.push_back(pop[i]);
        }
        return result;
    }

    // UUID (RFC 4122 v4)
    void uuid(uint64_t& hi, uint64_t& lo) noexcept;
    void uuid_bytes(uint8_t out[16]) noexcept;

    // State management
    [[nodiscard]] State save_state() const noexcept;
    void restore_state(const State& s) noexcept;
    [[nodiscard]] uint64_t get_counter() const noexcept;

    // Salta 2^128 stati (per parallelismo)
    void jump() noexcept;

    // Test statistico
    [[nodiscard]] double test_uniformity(size_t samples = 100000, size_t buckets = 100);

private:
    class Impl;
    Impl* pimpl;
};

#endif // RANDOM_H