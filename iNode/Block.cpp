#include "Block.h"

#include <iostream>
#include <chrono>

#include <OpenES/OES.h>
#include <OpenES/layer/interface.h>

// ====================== Static Members ======================
OES *Block::s_cipher = nullptr;
Block::NameResolver Block::s_nameResolver = nullptr;
Block::NameWriter Block::s_nameWriter = nullptr;
void *Block::s_resolverCtx = nullptr;
void *Block::s_writerCtx = nullptr;

// ====================== Constructor / Destructor ======================
Block::Block() noexcept {
    reset();
}

Block::~Block() = default;

// ====================== Static Configuration ======================
void Block::setCipherEngine(OES *engine) noexcept { s_cipher = engine; }
OES *Block::getCipherEngine() noexcept { return s_cipher; }

void Block::setNameResolver(NameResolver resolver, void *ctx) noexcept {
    s_nameResolver = std::move(resolver);
    s_resolverCtx = ctx;
}

void Block::setNameWriter(NameWriter writer, void *ctx) noexcept {
    s_nameWriter = std::move(writer);
    s_writerCtx = ctx;
}

// ====================== Name Storage Internals ======================
bool Block::isNameInline() const noexcept {
    return name_offset == 0 && name_len <= INLINE_NAME_SIZE;
}

size_t Block::getNameLength() const noexcept { return name_len; }

std::string Block::getStoredName() const {
    if (name_len == 0) return {};

    if (isNameInline()) {
        return {name_inline, name_len};
    }

    // External name: use resolver
    if (s_nameResolver) [[likely]] {
        return s_nameResolver(name_offset, name_len, s_resolverCtx);
    }
    return {};
}

void Block::storeName(std::string_view encryptedName) {
    name_len = static_cast<uint16_t>(encryptedName.length());

    if (name_len == 0) {
        name_inline[0] = '\0';
        name_offset = 0;
        return;
    }

    if (name_len <= INLINE_NAME_SIZE) {
        // Inline storage
        std::memcpy(name_inline, encryptedName.data(), name_len);
        if (name_len < INLINE_NAME_SIZE) {
            name_inline[name_len] = '\0';
        }
        name_offset = 0;
    } else {
        // External storage
        if (s_nameWriter) [[likely]] {
            name_offset = s_nameWriter(encryptedName, s_writerCtx);
            std::memset(name_inline, 0, INLINE_NAME_SIZE);
        } else {
            // Fallback: truncate
            std::memcpy(name_inline, encryptedName.data(), INLINE_NAME_SIZE);
            name_len = INLINE_NAME_SIZE;
            name_offset = 0;
        }
    }
}

// ====================== Name Encryption/Decryption ======================
std::string Block::encryptName(std::string_view plainName) {
    if (!s_cipher || plainName.empty()) [[unlikely]] {
        return std::string(plainName);
    }

    try {
        s_cipher->resetBlocks();
        s_cipher->load_data_raw(const_cast<char *>(plainName.data()), plainName.length());
        s_cipher->enc_adv();

        auto *cb = s_cipher->get_cipherBlock();

        if (!cb || cb->isNull()) [[unlikely]] {
            return std::string(plainName);
        }

        auto [exp, len] = exportBlock(cb, OES_TYPE_RAW_UINT8);

        if (!exp || len == 0) [[unlikely]] {
            return std::string(plainName);
        }

        std::string result(static_cast<char *>(exp), len);
        free(exp);
        return result;
    } catch (const std::exception &_) {
        return std::string(plainName);
    } catch (...) {
        return std::string(plainName);
    }
}

std::string Block::decryptName(std::string_view encName) {
    if (!s_cipher || encName.empty()) [[unlikely]] {
        return std::string(encName);
    }

    try {
        auto *ib = importBlock(encName.data(), encName.length(), OES_TYPE_RAW_UINT8);
        if (!ib) [[unlikely]]
                return std::string(encName);

        s_cipher->resetBlocks();
        s_cipher->load_cipher_block(ib, true);
        s_cipher->dec_adv();

        auto *pb = s_cipher->get_plainBlock();

        if (!pb || pb->isNull()) [[unlikely]]
                return std::string(encName);

        auto [bytes, len] = pb->toBytes();

        if (!bytes || len == 0) [[unlikely]]
                return std::string(encName);

        std::string result(reinterpret_cast<char *>(bytes), len);

        delete[] bytes;
        return result;
    } catch (const std::exception &_) {
        return std::string(encName);
    } catch (...) {
        return std::string(encName);
    }
}

// ====================== Name Management (Public API) ======================
void Block::setName(const char *plainName) {
    if (!plainName) [[unlikely]] {
        storeName({});
        return;
    }
    setName(std::string_view(plainName, std::strlen(plainName)));
}

void Block::setName(std::string_view plainName) {
    if (plainName.empty()) [[unlikely]] {
        storeName({});
        return;
    }
    std::string encrypted = encryptName(plainName);
    storeName(encrypted);
}

std::string Block::getPlainName() const {
    std::string stored = getStoredName();
    if (stored.empty()) return {};
    return decryptName(stored);
}

const char *Block::getRawName() const noexcept {
    return name_inline;
}

bool Block::nameEquals(const char *plainName) const {
    return plainName && getPlainName() == plainName;
}

bool Block::nameEquals(std::string_view plainName) const {
    return getPlainName() == plainName;
}

// ====================== Timestamp Management ======================
void Block::setCreatedNow() noexcept {
    created_at = static_cast<uint64_t>(std::time(nullptr));
}

void Block::setModifiedNow() noexcept {
    modified_at = static_cast<uint64_t>(std::time(nullptr));
}

void Block::setAccessedNow() noexcept {
    accessed_at = static_cast<uint64_t>(std::time(nullptr));
}

std::string Block::getCreatedAtStr() const {
    if (created_at == 0) return "N/A";
    auto t = static_cast<std::time_t>(created_at);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buf;
}

std::string Block::getModifiedAtStr() const {
    if (modified_at == 0) return "N/A";
    auto t = static_cast<std::time_t>(modified_at);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buf;
}

std::string Block::getAccessedAtStr() const {
    if (accessed_at == 0) return "N/A";
    auto t = static_cast<std::time_t>(accessed_at);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buf;
}

// ====================== Core Methods ======================
void Block::reset() noexcept {
    std::memset(this, 0, sizeof(Block));
}

bool Block::isFileBlock() const noexcept { return isFile; }
bool Block::isDirectoryBlock() const noexcept { return !isFile; }

void Block::copyFrom(const Block *other) noexcept {
    if (other) [[likely]]
            std::memcpy(this, other, sizeof(Block));
}

void Block::print() const {
    const auto pn = getPlainName();
    const bool inl = isNameInline();

    std::cout << "╔════════════════════════════════════════════════════════════════════╗\n"
            << "║                           BLOCK INFO                               ║\n"
            << "╠════════════════════════════════════════════════════════════════════╣\n"
            << "║ Name (plain):  " << std::left << std::setw(52) << pn << "║\n"
            << "║ Name length:   " << std::left << std::setw(52) << name_len << "║\n"
            << "║ Name storage:  " << std::left << std::setw(52)
            << (inl ? "INLINE" : "EXTERNAL @" + std::to_string(name_offset)) << "║\n"
            << "║ Type:          " << std::left << std::setw(52)
            << (isFile ? "FILE" : "DIRECTORY") << "║\n"
            << "║ Current Pos:   " << std::left << std::setw(52) << current << "║\n"
            << "║ Parent Pos:    " << std::left << std::setw(52) << parent << "║\n"
            << "║ Level:         " << std::left << std::setw(52) << level << "║\n"
            << "╠════════════════════════════════════════════════════════════════════╣\n"
            << "║ TIMESTAMPS                                                         ║\n"
            << "║ Created:       " << std::left << std::setw(52) << getCreatedAtStr() << "║\n"
            << "║ Modified:      " << std::left << std::setw(52) << getModifiedAtStr() << "║\n"
            << "║ Accessed:      " << std::left << std::setw(52) << getAccessedAtStr() << "║\n"
            << "╠════════════════════════════════════════════════════════════════════╣\n";

    if (isFile) {
        std::cout << "║ FILE SPECIFIC:                                                     ║\n"
                << "║ Data Pos:      " << std::left << std::setw(52) << data_pos << "║\n"
                << "║ Size:          " << std::left << std::setw(52) << size << "║\n";
    } else {
        std::cout << "║ DIRECTORY SPECIFIC:                                                ║\n"
                << "║ Subdir Pos:    " << std::left << std::setw(52) << subdir_pos << "║\n"
                << "║ Data Pos:      " << std::left << std::setw(52) << data_pos << "║\n"
                << "║ Files:         " << std::left << std::setw(52) << files_n << "║\n"
                << "║ Folders:       " << std::left << std::setw(52) << folders_n << "║\n";
    }

    std::cout << "╠════════════════════════════════════════════════════════════════════╣\n"
            << "║ LINKED LIST:                                                       ║\n"
            << "║ Next:          " << std::left << std::setw(52) << next << "║\n"
            << "║ Previous:      " << std::left << std::setw(52) << previous << "║\n"
            << "╚════════════════════════════════════════════════════════════════════╝\n";
}

bool Block::isValid() const noexcept {
    // Name consistency check
    if (name_len > 0 && name_len > INLINE_NAME_SIZE && name_offset == 0)
        return false;

    if (isFile)
        return subdir_pos == 0 && folders_n == 0 && !(data_pos > 0 && size == 0);

    return size == 0;
}

// ====================== Type Queries ======================
bool Block::isRoot() const noexcept {
    return level == 0 && parent == 0 && name_len == 4 &&
           std::memcmp(name_inline, "root", 4) == 0;
}

bool Block::isLeaf() const noexcept {
    return isFile || (subdir_pos == 0 && data_pos == 0);
}

bool Block::hasChildren() const noexcept {
    return !isFile && (subdir_pos | data_pos);
}

bool Block::hasSiblings() const noexcept {
    return next | previous;
}

size_t Block::getTotalEntries() const noexcept {
    return isFile ? 0 : files_n + folders_n;
}

// ====================== Linking Helpers ======================
void Block::linkAfter(Block *pred) noexcept {
    if (!pred) [[unlikely]] return;
    previous = pred->current;
    next = pred->next;
    pred->next = current;
}

void Block::linkBefore(Block *succ) noexcept {
    if (!succ) [[unlikely]] return;
    next = succ->current;
    previous = succ->previous;
    succ->previous = current;
}

void Block::unlink() noexcept {
    previous = next = 0;
}

// ====================== Comparison ======================
bool Block::equals(const Block *other) const noexcept {
    return other && std::memcmp(this, other, sizeof(Block)) == 0;
}

// ====================== Factory Methods ======================
std::unique_ptr<Block> Block::clone() const {
    auto copy = std::make_unique<Block>();
    std::memcpy(copy.get(), this, sizeof(Block));
    return copy;
}

std::unique_ptr<Block> Block::createFile(const char *plainName, size_t fileSize,
                                         size_t parentPos, size_t dataPos, size_t depth) {
    auto b = std::make_unique<Block>();
    b->setName(plainName);
    b->isFile = true;
    b->parent = parentPos;
    b->data_pos = dataPos;
    b->size = fileSize;
    b->level = static_cast<uint32_t>(depth);
    b->setCreatedNow();
    b->setModifiedNow();
    return b;
}

std::unique_ptr<Block> Block::createDirectory(const char *plainName,
                                              size_t parentPos, size_t depth) {
    auto b = std::make_unique<Block>();
    b->setName(plainName);
    b->isFile = false;
    b->parent = parentPos;
    b->level = static_cast<uint32_t>(depth);
    b->setCreatedNow();
    b->setModifiedNow();
    return b;
}

std::unique_ptr<Block> Block::createRoot() {
    auto b = std::make_unique<Block>();
    std::memcpy(b->name_inline, "root", 5);
    b->name_len = 4;
    b->name_offset = 0;
    b->isFile = false;
    b->setCreatedNow();
    b->setModifiedNow();
    return b;
}
