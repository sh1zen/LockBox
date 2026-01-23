#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <memory>
#include <functional>

class OES;

class Block {
public:
    // ====================== Constants ======================
    static constexpr size_t INLINE_NAME_SIZE = 256;

    // ====================== Callback Types ======================
    using NameResolver = std::function<std::string(size_t offset, size_t len, void *ctx)>;
    using NameWriter = std::function<size_t(std::string_view name, void *ctx)>;

    // ====================== Data Members ======================
    // Name storage (hybrid: inline for short names, external for long)
    char name_inline[INLINE_NAME_SIZE] = {0};
    uint16_t name_len = 0;
    size_t name_offset = 0; // 0 = inline, >0 = external storage offset

    // Type and hierarchy
    bool isFile = false;
    uint32_t level = 0;

    // Position tracking
    size_t current = 0;
    size_t parent = 0;
    size_t next = 0;
    size_t previous = 0;

    // Directory-specific
    size_t subdir_pos = 0;
    size_t data_pos = 0;
    uint32_t files_n = 0;
    uint32_t folders_n = 0;

    // File-specific
    size_t size = 0;

    // Timestamps (Unix timestamps)
    uint64_t created_at = 0;
    uint64_t modified_at = 0;
    uint64_t accessed_at = 0;

    // Reserved for future use
    uint8_t reserved[32] = {0};

    // ====================== Constructor / Destructor ======================
    Block() noexcept;

    ~Block();

    Block(const Block &) = default;

    Block &operator=(const Block &) = default;

    Block(Block &&) = default;

    Block &operator=(Block &&) = default;

    // ====================== Static Configuration ======================
    static void setCipherEngine(OES *engine) noexcept;

    static OES *getCipherEngine() noexcept;

    static void setNameResolver(NameResolver resolver, void *ctx = nullptr) noexcept;

    static void setNameWriter(NameWriter writer, void *ctx = nullptr) noexcept;

    // ====================== Name Management ======================
    void setName(const char *plainName);

    void setName(std::string_view plainName);

    std::string getPlainName() const;

    std::string getStoredName() const;

    const char *getRawName() const noexcept;

    bool nameEquals(const char *plainName) const;

    bool nameEquals(std::string_view plainName) const;

    bool isNameInline() const noexcept;

    size_t getNameLength() const noexcept;

    // ====================== Timestamp Management ======================
    void setCreatedNow() noexcept;

    void setModifiedNow() noexcept;

    void setAccessedNow() noexcept;

    uint64_t getCreatedAt() const noexcept { return created_at; }
    uint64_t getModifiedAt() const noexcept { return modified_at; }
    uint64_t getAccessedAt() const noexcept { return accessed_at; }

    std::string getCreatedAtStr() const;

    std::string getModifiedAtStr() const;

    std::string getAccessedAtStr() const;

    // ====================== Core Methods ======================
    void reset() noexcept;

    void copyFrom(const Block *other) noexcept;

    void print() const;

    bool isValid() const noexcept;

    // ====================== Type Queries ======================
    bool isFileBlock() const noexcept;

    bool isDirectoryBlock() const noexcept;

    bool isRoot() const noexcept;

    bool isLeaf() const noexcept;

    bool hasChildren() const noexcept;

    bool hasSiblings() const noexcept;

    size_t getTotalEntries() const noexcept;

    // ====================== Linking Helpers ======================
    void linkAfter(Block *pred) noexcept;

    void linkBefore(Block *succ) noexcept;

    void unlink() noexcept;

    // ====================== Comparison ======================
    bool equals(const Block *other) const noexcept;

    // ====================== Factory Methods ======================
    [[nodiscard]] std::unique_ptr<Block> clone() const;

    static std::unique_ptr<Block> createFile(const char *plainName, size_t fileSize = 0,
                                             size_t parentPos = 0, size_t dataPos = 0,
                                             size_t depth = 0);

    static std::unique_ptr<Block> createDirectory(const char *plainName,
                                                  size_t parentPos = 0, size_t depth = 0);

    static std::unique_ptr<Block> createRoot();

private:
    // ====================== Static Members ======================
    static OES *s_cipher;
    static NameResolver s_nameResolver;
    static NameWriter s_nameWriter;
    static void *s_resolverCtx;
    static void *s_writerCtx;

    // ====================== Internal Helpers ======================
    void storeName(std::string_view encryptedName);

    static std::string encryptName(std::string_view plainName);

    static std::string decryptName(std::string_view encName);
};
