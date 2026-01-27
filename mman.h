#ifndef MMAN_H
#define MMAN_H

#include <cstdint>

// ====================== POSIX-compatible constants ======================

#ifndef PROT_NONE
#define PROT_NONE   0
#define PROT_READ   1
#define PROT_WRITE  2
#define PROT_EXEC   4
#endif

#ifndef MAP_FILE
#define MAP_FILE      0
#define MAP_SHARED    1
#define MAP_PRIVATE   2
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON      MAP_ANONYMOUS
#endif

#ifndef MS_ASYNC
#define MS_ASYNC      1
#define MS_SYNC       2
#define MS_INVALIDATE 4
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void*)(~(size_t)0))
#endif

// ====================== Types ======================

#ifdef _WIN32
using mman_offset_t = int64_t;
#else
using mman_offset_t = off_t;
#endif

// ====================== C Interface ======================

#ifdef __cplusplus
extern "C" {
#endif

void *mmap(void *addr, size_t len, int prot, int flags, int fd, mman_offset_t offset);

int munmap(void *addr, size_t len);

int mprotect(void *addr, size_t len, int prot);

int msync(void *addr, size_t len, int flags);

int mlock(const void *addr, size_t len);

int munlock(const void *addr, size_t len);

#ifdef __cplusplus
}
#endif

// ====================== C++ Interface ======================

#ifdef __cplusplus

#include <system_error>

namespace mman {
    // ====================== Enums ======================

    enum class Prot : int {
        None = PROT_NONE,
        Read = PROT_READ,
        Write = PROT_WRITE,
        Exec = PROT_EXEC
    };

    constexpr Prot operator|(Prot a, Prot b) noexcept {
        return static_cast<Prot>(static_cast<int>(a) | static_cast<int>(b));
    }

    constexpr int operator&(Prot a, Prot b) noexcept {
        return static_cast<int>(a) & static_cast<int>(b);
    }

    enum class MapFlags : int {
        File = MAP_FILE,
        Shared = MAP_SHARED,
        Private = MAP_PRIVATE,
        Fixed = MAP_FIXED,
        Anonymous = MAP_ANONYMOUS
    };

    constexpr MapFlags operator|(MapFlags a, MapFlags b) noexcept {
        return static_cast<MapFlags>(static_cast<int>(a) | static_cast<int>(b));
    }

    constexpr int operator&(MapFlags a, MapFlags b) noexcept {
        return static_cast<int>(a) & static_cast<int>(b);
    }

    enum class SyncFlags : int {
        Async = MS_ASYNC,
        Sync = MS_SYNC,
        Invalidate = MS_INVALIDATE
    };

    // ====================== Result Types ======================

    struct MapResult {
        void *ptr = MAP_FAILED;
        std::error_code error{};

        [[nodiscard]] bool ok() const noexcept { return ptr != MAP_FAILED; }
        [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
    };

    struct OpResult {
        bool success = false;
        std::error_code error{};

        [[nodiscard]] explicit operator bool() const noexcept { return success; }
    };

    // ====================== Functions ======================

    MapResult map(void *addr, size_t len, Prot prot, MapFlags flags, int fd = -1, mman_offset_t offset = 0) noexcept;

    OpResult unmap(void *addr, size_t len) noexcept;

    OpResult protect(void *addr, size_t len, Prot prot) noexcept;

    OpResult sync(void *addr, size_t len, SyncFlags flags = SyncFlags::Sync) noexcept;

    OpResult lock(const void *addr, size_t len) noexcept;

    OpResult unlock(const void *addr, size_t len) noexcept;

    // ====================== RAII Wrapper ======================

    class MappedMemory {
    public:
        MappedMemory() = default;

        MappedMemory(void *addr, size_t len, Prot prot, MapFlags flags,
                     int fd = -1, mman_offset_t offset = 0);

        ~MappedMemory();

        // Move only
        MappedMemory(MappedMemory &&other) noexcept;

        MappedMemory &operator=(MappedMemory &&other) noexcept;

        MappedMemory(const MappedMemory &) = delete;

        MappedMemory &operator=(const MappedMemory &) = delete;

        void reset() noexcept;

        void *release() noexcept;

        [[nodiscard]] void *get() const noexcept { return ptr_; }
        [[nodiscard]] size_t size() const noexcept { return size_; }
        [[nodiscard]] explicit operator bool() const noexcept { return ptr_ != nullptr; }

        template<typename T>
        [[nodiscard]] T *as() const noexcept { return static_cast<T *>(ptr_); }

    private:
        void *ptr_ = nullptr;
        size_t size_ = 0;
    };
} // namespace mman

#endif // __cplusplus
#endif // MMAN_H
