#include "mman.h"
#include <cerrno>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <io.h>

// ====================== Windows Implementation ======================

namespace {
    // Lookup tables for protection flags
    constexpr DWORD kPageProtect[] = {
        0, // 0: NONE
        PAGE_READONLY, // 1: READ
        PAGE_READWRITE, // 2: WRITE
        PAGE_READWRITE, // 3: READ|WRITE
        PAGE_EXECUTE, // 4: EXEC
        PAGE_EXECUTE_READ, // 5: EXEC|READ
        PAGE_EXECUTE_READWRITE, // 6: EXEC|WRITE
        PAGE_EXECUTE_READWRITE // 7: EXEC|READ|WRITE
    };

    constexpr DWORD kFileMapAccess[] = {
        0,
        FILE_MAP_READ,
        FILE_MAP_WRITE,
        FILE_MAP_READ | FILE_MAP_WRITE,
        FILE_MAP_EXECUTE,
        FILE_MAP_EXECUTE | FILE_MAP_READ,
        FILE_MAP_EXECUTE | FILE_MAP_WRITE,
        FILE_MAP_EXECUTE | FILE_MAP_READ | FILE_MAP_WRITE
    };

    inline DWORD toPageProtect(int prot) noexcept {
        return kPageProtect[prot & 0x7];
    }

    inline DWORD toFileAccess(int prot) noexcept {
        return kFileMapAccess[prot & 0x7];
    }

    inline int windowsErrorToErrno(DWORD error) noexcept {
        switch (error) {
            case ERROR_INVALID_HANDLE: return EBADF;
            case ERROR_INVALID_PARAMETER: return EINVAL;
            case ERROR_NOT_ENOUGH_MEMORY: return ENOMEM;
            case ERROR_ACCESS_DENIED: return EACCES;
            case ERROR_FILE_NOT_FOUND: return ENOENT;
            case ERROR_DISK_FULL: return ENOSPC;
            default: return EINVAL;
        }
    }

    inline void setErrnoFromWindows() noexcept {
        errno = windowsErrorToErrno(GetLastError());
    }
} // anonymous namespace

// ====================== C Interface (Windows) ======================

extern "C" {
void *mmap(void *addr, size_t len, int prot, int flags, int fd, mman_offset_t offset) {
    if (len == 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    const bool anonymous = (flags & MAP_ANONYMOUS) != 0;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;

    if (!anonymous) {
        fileHandle = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
        if (fileHandle == INVALID_HANDLE_VALUE) {
            errno = EBADF;
            return MAP_FAILED;
        }
    }

    DWORD protect = toPageProtect(prot);
    DWORD access = toFileAccess(prot);

    // Handle copy-on-write for MAP_PRIVATE
    if ((flags & MAP_PRIVATE) != 0 && !anonymous) {
        protect = PAGE_WRITECOPY;
        access = FILE_MAP_COPY;
    }

    uint64_t maxSize = static_cast<uint64_t>(offset) + len;
    auto maxSizeHigh = static_cast<DWORD>(maxSize >> 32);
    auto maxSizeLow = static_cast<DWORD>(maxSize & 0xFFFFFFFF);

    HANDLE mapping = CreateFileMappingW(
        fileHandle, nullptr, protect,
        maxSizeHigh, maxSizeLow, nullptr
    );

    if (!mapping) {
        setErrnoFromWindows();
        return MAP_FAILED;
    }

    auto offsetHigh = static_cast<DWORD>(static_cast<uint64_t>(offset) >> 32);
    auto offsetLow = static_cast<DWORD>(offset & 0xFFFFFFFF);

    void *result;
    if ((flags & MAP_FIXED) != 0) {
        result = MapViewOfFileEx(mapping, access, offsetHigh, offsetLow, len, addr);
    } else {
        result = MapViewOfFile(mapping, access, offsetHigh, offsetLow, len);
    }

    CloseHandle(mapping);

    if (!result) {
        setErrnoFromWindows();
        return MAP_FAILED;
    }

    return result;
}

int munmap(void *addr, size_t len) {
    (void) len; // Windows ignora la lunghezza
    if (UnmapViewOfFile(addr)) {
        return 0;
    }
    setErrnoFromWindows();
    return -1;
}

int mprotect(void *addr, size_t len, int prot) {
    DWORD oldProtect;
    if (VirtualProtect(addr, len, toPageProtect(prot), &oldProtect)) {
        return 0;
    }
    setErrnoFromWindows();
    return -1;
}

int msync(void *addr, size_t len, int flags) {
    (void) flags; // Windows fa sempre sync sincrono
    if (FlushViewOfFile(addr, len)) {
        return 0;
    }
    setErrnoFromWindows();
    return -1;
}

int mlock(const void *addr, size_t len) {
    if (VirtualLock(const_cast<void *>(addr), len)) {
        return 0;
    }
    setErrnoFromWindows();
    return -1;
}

int munlock(const void *addr, size_t len) {
    if (VirtualUnlock(const_cast<void *>(addr), len)) {
        return 0;
    }
    setErrnoFromWindows();
    return -1;
}
} // extern "C"

#else // Unix/Linux/macOS

// ====================== Unix Implementation ======================
// Le funzioni sono già fornite da <sys/mman.h>, niente da implementare

#include <sys/mman.h>

#endif // _WIN32

// ====================== C++ Interface ======================

namespace mman {
    namespace {
        inline std::error_code lastError() noexcept {
            return {
#ifdef _WIN32
                std::error_code(static_cast<int>(GetLastError()), std::system_category())
#else
                std::error_code(errno, std::generic_category())
#endif

            };
        }
    } // anonymous namespace

    MapResult map(void *addr, size_t len, Prot prot, MapFlags flags,
                  int fd, mman_offset_t offset) noexcept {
        void *ptr = ::mmap(addr, len, static_cast<int>(prot),
                           static_cast<int>(flags), fd, offset);
        if (ptr == MAP_FAILED) {
            return {MAP_FAILED, lastError()};
        }
        return {ptr, {}};
    }

    OpResult unmap(void *addr, size_t len) noexcept {
        if (::munmap(addr, len) == 0) {
            return {true, {}};
        }
        return {false, lastError()};
    }

    OpResult protect(void *addr, size_t len, Prot prot) noexcept {
        if (::mprotect(addr, len, static_cast<int>(prot)) == 0) {
            return {true, {}};
        }
        return {false, lastError()};
    }

    OpResult sync(void *addr, size_t len, SyncFlags flags) noexcept {
        if (::msync(addr, len, static_cast<int>(flags)) == 0) {
            return {true, {}};
        }
        return {false, lastError()};
    }

    OpResult lock(const void *addr, size_t len) noexcept {
        if (::mlock(addr, len) == 0) {
            return {true, {}};
        }
        return {false, lastError()};
    }

    OpResult unlock(const void *addr, size_t len) noexcept {
        if (::munlock(addr, len) == 0) {
            return {true, {}};
        }
        return {false, lastError()};
    }

    // ====================== MappedMemory Implementation ======================

    MappedMemory::MappedMemory(void *addr, size_t len, Prot prot, MapFlags flags,
                               int fd, mman_offset_t offset)
        : size_(len) {
        auto result = map(addr, len, prot, flags, fd, offset);
        ptr_ = result.ok() ? result.ptr : nullptr;
    }

    MappedMemory::~MappedMemory() {
        reset();
    }

    MappedMemory::MappedMemory(MappedMemory &&other) noexcept
        : ptr_(other.ptr_), size_(other.size_) {
        other.ptr_ = nullptr;
        other.size_ = 0;
    }

    MappedMemory &MappedMemory::operator=(MappedMemory &&other) noexcept {
        if (this != &other) {
            reset();
            ptr_ = other.ptr_;
            size_ = other.size_;
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    void MappedMemory::reset() noexcept {
        if (ptr_) {
            (void) unmap(ptr_, size_);
            ptr_ = nullptr;
            size_ = 0;
        }
    }

    void *MappedMemory::release() noexcept {
        void *p = ptr_;
        ptr_ = nullptr;
        size_ = 0;
        return p;
    }
} // namespace mman
