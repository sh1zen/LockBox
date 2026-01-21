#pragma once

#include "Block.h"
#include "inode_raw.h"

class OES;

class iNode {
public:
    struct DirEntry {
        std::string name; // Decrypted name for display
        std::string encryptedName; // Raw stored name
        bool isFile;
        size_t size;
    };

    struct Stats {
        size_t totalSize;
        size_t usedSpace;
        size_t freeSpace;
        size_t dirCount;
        size_t fileCount;
    };

    using WalkCallback = std::function<void(Block *, const std::string &, iNode *)>;

    // ═══════════════════════════════════════════════════════════════════════
    // LIFECYCLE
    // ═══════════════════════════════════════════════════════════════════════
    explicit iNode(const std::string &path, OES *engine = nullptr);

    ~iNode();

    // Non-copyable
    iNode(const iNode &) = delete;

    iNode &operator=(const iNode &) = delete;

    // ═══════════════════════════════════════════════════════════════════════
    // FILE OPERATIONS (Plain paths)
    // ═══════════════════════════════════════════════════════════════════════

    size_t addFile(const std::string &plainPath, const char *data, size_t size);

    std::pair<char *, size_t> readFile(const std::string &plainPath);

    bool updateFile(const std::string &plainPath, const char *data, size_t size);

    bool removeFile(const std::string &plainPath);

    size_t importFile(const std::string &plainPath, const std::string &externalPath);

    // ═══════════════════════════════════════════════════════════════════════
    // DIRECTORY OPERATIONS (Plain paths)
    // ═══════════════════════════════════════════════════════════════════════

    size_t addDirectory(const std::string &plainPath);

    bool removeDirectory(const std::string &plainPath, bool force = false);

    bool removeDirectoryRecursive(const std::string &plainPath);

    std::vector<DirEntry> listDirectory(const std::string &plainPath) const;

    // ═══════════════════════════════════════════════════════════════════════
    // COMMON OPERATIONS (Plain paths)
    // ═══════════════════════════════════════════════════════════════════════

    bool exists(const std::string &plainPath, bool isFile) const;

    bool rename(const std::string &plainPath, const std::string &newPlainName);

    bool move(const std::string &srcPlainPath, const std::string &destPlainPath);

    bool copy(const std::string &srcPlainPath, const std::string &destPlainPath);

    bool remove(const std::string &plainPath);

    // ═══════════════════════════════════════════════════════════════════════
    // SEARCH & TRAVERSAL
    // ═══════════════════════════════════════════════════════════════════════

    std::vector<std::string> search(const std::string &name, bool caseSensitive = false);

    void walk(WalkCallback callback);

    void walk(const std::string &startPlainPath, WalkCallback callback);

    size_t countSubdirs(const std::string &plainPath) const;

    size_t countFiles(const std::string &plainPath) const;

    // ═══════════════════════════════════════════════════════════════════════
    // DISPLAY & STATS
    // ═══════════════════════════════════════════════════════════════════════

    void display() const;

    Stats getStats() const;

    void printStats() const;

    // ═══════════════════════════════════════════════════════════════════════
    // EXPORT & PERSISTENCE
    // ═══════════════════════════════════════════════════════════════════════

    void save();

    void exportTo(const std::string &exportPath);

    void exportTo(const std::string &exportPath, const std::string &internalPlainPath);

    // ═══════════════════════════════════════════════════════════════════════
    // BUILDER & IMPORT
    // ═══════════════════════════════════════════════════════════════════════

    static std::unique_ptr<iNode> buildFromFilesystem(const std::string &fsPath,
                                                      const std::string &inodePath,
                                                      OES *cipherEngine = nullptr);

    // ═══════════════════════════════════════════════════════════════════════
    // MAINTENANCE & ACCESSORS
    // ═══════════════════════════════════════════════════════════════════════

    bool defragment();

    const std::string &getFilePath() const;

    OES *getCipherEngine() const;

    // ═══════════════════════════════════════════════════════════════════════
    // LEGACY/COMPATIBILITY (deprecated - use plain path versions)
    // ═══════════════════════════════════════════════════════════════════════

    Block *findBlock(const std::string &path, bool isFile) const;

    Block *findParent(const std::string &path) const;

private:
    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL BLOCK OPERATIONS
    // ═══════════════════════════════════════════════════════════════════════

    void syncRoot() const;

    std::unique_ptr<Block> readBlockAt(size_t pos) const;

    std::unique_ptr<Block> cloneRoot() const;

    size_t insertBlock(Block *block);

    bool updateBlock(Block *block);

    bool deleteBlock(Block *block);

    bool unlinkBlock(Block *block);

    // Block finding (uses plain paths, Block handles encryption internally)
    std::unique_ptr<Block> findBlockByPath(const std::string &plainPath, bool isFile) const;

    std::unique_ptr<Block> findParentByPath(const std::string &plainPath) const;

    // Directory chain creation
    size_t ensureDirChain(const std::string &plainPath);

    size_t createFileBlock(const std::string &plainName, const char *encData,
                           size_t encSize, size_t parentPos);

    // File data operations
    std::pair<std::unique_ptr<char[]>, size_t> readFileData(Block *block) const;

    // ═══════════════════════════════════════════════════════════════════════
    // DATA ENCRYPTION (for file content only)
    // ═══════════════════════════════════════════════════════════════════════

    std::pair<char *, size_t> encryptData(const char *data, size_t size) const;

    std::pair<char *, size_t> decryptData(const char *data, size_t size) const;

    // ═══════════════════════════════════════════════════════════════════════
    // PATH UTILITIES
    // ═══════════════════════════════════════════════════════════════════════

    std::string normalizePath(const std::string &path) const;

    std::string getParentPath(const std::string &path) const;

    std::string getFileName(const std::string &path) const;

    std::string toLower(const std::string &str) const;

    // ═══════════════════════════════════════════════════════════════════════
    // COPY HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    bool copyFile(const std::string &srcPlainPath, const std::string &destPlainPath);

    bool copyDirectoryRecursive(const std::string &srcPlainPath, const std::string &destPlainPath);

    // ═══════════════════════════════════════════════════════════════════════
    // EXPORT HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    void exportRecursive(size_t pos, const std::string &destPath);

    void exportSingleFile(Block *block, const std::string &destPath);

    // ═══════════════════════════════════════════════════════════════════════
    // FILESYSTEM SCAN
    // ═══════════════════════════════════════════════════════════════════════

    void scanFilesystem(const std::string &fsPath, const std::string &internalPlainPath);

    // ═══════════════════════════════════════════════════════════════════════
    // WALK HELPER
    // ═══════════════════════════════════════════════════════════════════════

    void walkRecursiveInternal(size_t pos, uint32_t level,
                               const std::string &currentPlainPath,
                               WalkCallback callback);

    // ═══════════════════════════════════════════════════════════════════════
    // MEMBER VARIABLES
    // ═══════════════════════════════════════════════════════════════════════

    std::unique_ptr<Block> root_;
    mutable inode_raw storage_;
    OES *cipher_;
    std::string path_;
};
