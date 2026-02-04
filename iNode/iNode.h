#pragma once

#include "Block.h"
#include "inode_raw.h"

class OES;

class iNode {
public:
    static constexpr const char *LOG_INTERNAL_PATH = ".lockbox_log";

    // ═══════════════════════════════════════════════════════════════════════
    // TYPES
    // ═══════════════════════════════════════════════════════════════════════

    struct DirEntry {
        std::string rawName;
        std::string plainName;
        bool isFile;
        size_t size;
    };

    struct Stats {
        size_t totalSize;
        size_t usedSpace;
        size_t freeSpace; // Reclaimable via defragment()
        size_t fileCount;
        size_t dirCount;
    };

    using WalkCallback = std::function<void(Block *, const std::string &, iNode *)>;

    // ═══════════════════════════════════════════════════════════════════════
    // LIFECYCLE
    // ═══════════════════════════════════════════════════════════════════════

    explicit iNode(const std::string &path, OES *engine = nullptr);

    ~iNode();

    iNode(const iNode &) = delete;

    iNode &operator=(const iNode &) = delete;

    iNode(iNode &&) = default;

    iNode &operator=(iNode &&) = default;

    // ═══════════════════════════════════════════════════════════════════════
    // FILE OPERATIONS
    // ═══════════════════════════════════════════════════════════════════════

    size_t addFile(const std::string &plainPath, const char *data, size_t size);

    size_t addDirectory(const std::string &plainPath) const;

    bool removeFile(const std::string &plainPath) const;

    bool removeDirectory(const std::string &plainPath, bool force = false) const;

    bool removeDirectoryRecursive(const std::string &plainPath);

    bool remove(const std::string &plainPath);

    std::pair<char *, size_t> readFile(const std::string &plainPath) const;

    bool updateFile(const std::string &plainPath, const char *data, size_t size) const;

    bool exists(const std::string &plainPath, bool isFile) const;

    bool rename(const std::string &plainPath, const std::string &newName) const;

    bool move(const std::string &srcPath, const std::string &destPath) const;

    bool copy(const std::string &srcPath, const std::string &destPath);

    bool copyFile(const std::string &srcPath, const std::string &destPath);

    bool copyDirectoryRecursive(const std::string &srcPath, const std::string &destPath);

    size_t importFile(const std::string &plainPath, const std::string &externalPath);

    // ═══════════════════════════════════════════════════════════════════════
    // DIRECTORY LISTING & SEARCH
    // ═══════════════════════════════════════════════════════════════════════

    std::vector<DirEntry> listDirectory(const std::string &plainPath) const;

    std::vector<std::string> search(const std::string &name, bool caseSensitive = false);

    size_t countSubdirs(const std::string &plainPath) const;

    size_t countFiles(const std::string &plainPath) const;

    // ═══════════════════════════════════════════════════════════════════════
    // TRAVERSAL
    // ═══════════════════════════════════════════════════════════════════════

    void walk(const WalkCallback &callback);

    void walk(const std::string &startPath, const WalkCallback &callback);

    // ═══════════════════════════════════════════════════════════════════════
    // STATS & DISPLAY
    // ═══════════════════════════════════════════════════════════════════════

    Stats getStats() const;

    void printStats() const;

    void display() const;

    // ═══════════════════════════════════════════════════════════════════════
    // PERSISTENCE & EXPORT
    // ═══════════════════════════════════════════════════════════════════════

    void save();

    void exportTo(const std::string &exportPath);

    void exportTo(const std::string &exportPath, const std::string &internalPath);

    // Bulk mode: defer sync/log flushes until endBulkUpdate() for faster batch operations.
    void beginBulkUpdate() const;

    void endBulkUpdate() const;

    // ═══════════════════════════════════════════════════════════════════════
    // LOGGING
    // ═══════════════════════════════════════════════════════════════════════

    std::string getLog() const;

    void clearLog();

    size_t getLogSize() const;

    // ═══════════════════════════════════════════════════════════════════════
    // MAINTENANCE
    // ═══════════════════════════════════════════════════════════════════════

    /// Compacts the storage file, reclaiming space from deleted blocks
    bool defragment() const;

    // ═══════════════════════════════════════════════════════════════════════
    // QUERIES
    // ═══════════════════════════════════════════════════════════════════════

    const std::string &getFilePath() const;

    OES *getCipherEngine() const;

    // ═══════════════════════════════════════════════════════════════════════
    // STATIC FACTORY
    // ═══════════════════════════════════════════════════════════════════════

    static std::unique_ptr<iNode> buildFromFilesystem(const std::string &fsPath,
                                                      const std::string &inodePath,
                                                      OES *cipherEngine = nullptr);

    // ═══════════════════════════════════════════════════════════════════════
    // PATH UTILITIES
    // ═══════════════════════════════════════════════════════════════════════

    static std::string normalizePath(const std::string &path);

    static std::string getParentPath(const std::string &path);

    static std::string getFileName(const std::string &path);

    static std::string toLower(const std::string &str);

private:
    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL - Block Access
    // ═══════════════════════════════════════════════════════════════════════

    Block *blockAt(size_t pos) const;

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL - Sync
    // ═══════════════════════════════════════════════════════════════════════

    void syncRoot() const;

    void commitRoot() const;

    void sync() const;

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL - Encryption
    // ═══════════════════════════════════════════════════════════════════════

    std::pair<char *, size_t> encryptData(const char *data, size_t size) const;

    std::pair<char *, size_t> decryptData(const char *data, size_t size) const;

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL - Block Operations
    // ═══════════════════════════════════════════════════════════════════════

    size_t insertBlock(Block *block) const;

    void updateBlock(const Block *block) const;

    void unlinkBlock(const Block *block) const;

    Block *findBlock(const std::string &plainPath, bool isFile) const;

    Block *findParent(const std::string &plainPath) const;

    size_t ensureDirChain(const std::string &plainPath) const;

    size_t createFileBlock(const std::string &plainName, const char *encData,
                           size_t encSize, size_t parentPos) const;

    std::pair<std::unique_ptr<char[]>, size_t> readFileData(Block *block) const;

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL - Traversal
    // ═══════════════════════════════════════════════════════════════════════

    void walkIterative(size_t startPos, const std::string &basePath, const WalkCallback &cb);

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL - Export
    // ═══════════════════════════════════════════════════════════════════════

    void exportIterative(size_t startPos, const std::string &basePath) const;

    void exportSingleFile(Block *block, const std::string &destPath) const;

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL - Filesystem Import
    // ═══════════════════════════════════════════════════════════════════════

    void scanFilesystem(const std::string &fsPath, const std::string &internalPath);

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL - Logging
    // ═══════════════════════════════════════════════════════════════════════

    void logOperation(const std::string &op, const std::string &details) const;

    void appendLogEntries(const std::string &entries) const;

    // ═══════════════════════════════════════════════════════════════════════
    // MEMBERS
    // ═══════════════════════════════════════════════════════════════════════

    mutable std::unique_ptr<Block> root_;
    mutable inode_raw storage_;
    mutable size_t bulkDepth_ = 0;
    mutable bool pendingSync_ = false;
    mutable std::string pendingLogEntries_;
    OES *cipher_;
    std::string path_;
};
