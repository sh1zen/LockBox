#pragma once

#include <memory>

class OES;

class Block {
public:
    // Inline buffer per nomi corti (ottimizzazione cache)
    static constexpr size_t INLINE_NAME_SIZE = 64;

    // ====================== Data Members (mmap-compatible layout) ======================

    // Nome: se name_len <= INLINE_NAME_SIZE, stored inline
    //       se name_len > INLINE_NAME_SIZE, name_inline contiene offset nell'area nomi
    char name_inline[INLINE_NAME_SIZE]{};
    size_t name_len{}; // Lunghezza reale del nome (encrypted)
    size_t name_offset{}; // Offset nell'area nomi esterni (0 se inline)

    bool isFile{};
    size_t files_n{};
    size_t folders_n{};
    size_t current{};
    size_t parent{};
    size_t subdir_pos{};
    size_t data_pos{};
    size_t size{};
    size_t next{};
    size_t previous{};
    size_t level{};
    char _padding[4]{};

    // ====================== Lifecycle ======================
    Block() noexcept;

    ~Block();

    Block(const Block &) = delete;

    Block &operator=(const Block &) = delete;

    Block(Block &&) noexcept = default;

    Block &operator=(Block &&) noexcept = default;

    // ====================== External Name Storage ======================
    // Deve essere impostato dal filesystem manager che gestisce mmap
    using NameResolver = std::string(*)(size_t offset, size_t len, void *ctx);
    using NameWriter = size_t(*)(std::string_view data, void *ctx); // ritorna offset

    static void setNameResolver(NameResolver resolver, void *ctx) noexcept;

    static void setNameWriter(NameWriter writer, void *ctx) noexcept;

    // ====================== Cipher Engine ======================
    static void setCipherEngine(OES *engine) noexcept;

    [[nodiscard]] static OES *getCipherEngine() noexcept;

    // ====================== Name Management (API invariata) ======================
    void setName(const char *plainName);

    void setName(std::string_view plainName);

    [[nodiscard]] std::string getPlainName() const;

    [[nodiscard]] const char *getRawName() const noexcept; // Solo per nomi inline!

    [[nodiscard]] bool nameEquals(const char *plainName) const;

    [[nodiscard]] bool nameEquals(std::string_view plainName) const;

    // Nuovi metodi utili
    [[nodiscard]] bool isNameInline() const noexcept;

    [[nodiscard]] size_t getNameLength() const noexcept;

    // ====================== Core Methods ======================
    void reset() noexcept;

    [[nodiscard]] bool isFileBlock() const noexcept;

    [[nodiscard]] bool isDirectoryBlock() const noexcept;

    void copyFrom(const Block *other) noexcept;

    void print() const;

    [[nodiscard]] bool isValid() const noexcept;

    // ====================== Factory & Clone ======================
    [[nodiscard]] std::unique_ptr<Block> clone() const;

    [[nodiscard]] static std::unique_ptr<Block> createFile(const char *plainName, size_t fileSize,
                                                           size_t parentPos, size_t dataPos, size_t depth);

    [[nodiscard]] static std::unique_ptr<Block> createDirectory(const char *plainName,
                                                                size_t parentPos, size_t depth);

    [[nodiscard]] static std::unique_ptr<Block> createRoot();

    // ====================== Tree Utilities ======================
    [[nodiscard]] bool isRoot() const noexcept;

    [[nodiscard]] bool isLeaf() const noexcept;

    [[nodiscard]] bool hasChildren() const noexcept;

    [[nodiscard]] bool hasSiblings() const noexcept;

    [[nodiscard]] size_t getTotalEntries() const noexcept;

    // ====================== Linking Helpers ======================
    void linkAfter(Block *predecessor) noexcept;

    void linkBefore(Block *successor) noexcept;

    void unlink() noexcept;

    // ====================== Comparison ======================
    [[nodiscard]] bool equals(const Block *other) const noexcept;

private:
    static OES *s_cipher;
    static NameResolver s_nameResolver;
    static NameWriter s_nameWriter;
    static void *s_resolverCtx;
    static void *s_writerCtx;

    [[nodiscard]] static std::string encryptName(std::string_view plainName);

    [[nodiscard]] static std::string decryptName(std::string_view encName);

    // Recupera nome criptato (inline o esterno)
    [[nodiscard]] std::string getStoredName() const;

    // Salva nome criptato (sceglie inline o esterno)
    void storeName(std::string_view encryptedName);
};
