#ifndef INODE_H
#define INODE_H

#include "Block.h"
#include "inode_raw.h"

class OES;

class iNode {
public:
    // ====================== Types ======================
    struct DirEntry {
        std::string encryptedName;
        std::string name;
        bool isFile;
        size_t size;
    };

    struct Stats {
        size_t totalSize;
        size_t usedSpace;
        size_t freeSpace;
        size_t fileCount;
        size_t dirCount;
    };

    using WalkCallback = std::function<void(Block *, const std::string &, iNode *)>;

    // ====================== Constructor / Destructor ======================
    iNode(const std::string &path, OES *engine);

    ~iNode();

    iNode(const iNode &) = delete;

    iNode &operator=(const iNode &) = delete;

    // ====================== File Operations ======================
    size_t addFile(const std::string &plainPath, const char *data, size_t size);

    size_t addDirectory(const std::string &plainPath);

    bool removeFile(const std::string &plainPath);

    bool removeDirectory(const std::string &plainPath, bool force = false);

    bool removeDirectoryRecursive(const std::string &plainPath);

    bool remove(const std::string &plainPath);

    std::pair<char *, size_t> readFile(const std::string &plainPath);

    bool updateFile(const std::string &plainPath, const char *data, size_t size);

    bool exists(const std::string &plainPath, bool isFile) const;

    bool rename(const std::string &plainPath, const std::string &newPlainName);

    bool move(const std::string &srcPlainPath, const std::string &destPlainPath);

    bool copy(const std::string &srcPlainPath, const std::string &destPlainPath);

    bool copyFile(const std::string &srcPlainPath, const std::string &destPlainPath);

    bool copyDirectoryRecursive(const std::string &srcPlainPath, const std::string &destPlainPath);

    size_t importFile(const std::string &plainPath, const std::string &externalPath);

    // ====================== Directory Listing ======================
    std::vector<DirEntry> listDirectory(const std::string &plainPath) const;

    size_t countSubdirs(const std::string &plainPath) const;

    size_t countFiles(const std::string &plainPath) const;

    // ====================== Search & Traversal ======================
    std::vector<std::string> search(const std::string &name, bool caseSensitive = true);

    void walk(WalkCallback callback);

    void walk(const std::string &startPlainPath, WalkCallback callback);

    // ====================== Display & Stats ======================
    void display();

    Stats getStats() const;

    void printStats() const;

    // ====================== Export & Persistence ======================
    void save();

    void exportTo(const std::string &exportPath);

    void exportTo(const std::string &exportPath, const std::string &internalPlainPath);

    // ====================== Builder & Import ======================
    static std::unique_ptr<iNode> buildFromFilesystem(const std::string &fsPath,
                                                      const std::string &inodePath,
                                                      OES *cipherEngine);

    // ====================== Maintenance & Accessors ======================
    bool defragment() const;

    void preallocate(size_t bytes);

    const std::string &getFilePath() const;

    OES *getCipherEngine() const;

    // ====================== Logging System ======================
    std::string getLog() const;

    void clearLog();

    size_t getLogSize() const;

    // ====================== Path Utilities ======================
    static std::string normalizePath(const std::string &path);

    static std::string getParentPath(const std::string &path);

    static std::string getFileName(const std::string &path);

    static std::string toLower(const std::string &str);

    void syncRoot() const;

private:
    // ====================== Constants ======================
    static constexpr const char *LOG_INTERNAL_PATH = ".lockbox_log";

    // ====================== Data Members ======================
    mutable inode_raw storage_;
    std::unique_ptr<Block> root_;
    OES *cipher_;
    std::string path_;

    // ====================== Synchronization ======================
    void commitRoot() const;

    void sync() const;

    // ====================== Direct Block Access (zero-copy) ======================
    Block *blockAt(size_t pos) const;

    void ensureCapacity(size_t needed) const;

    // ====================== Encryption ======================
    std::pair<char *, size_t> encryptData(const char *data, size_t size) const;

    std::pair<char *, size_t> decryptData(const char *data, size_t size) const;

    // ====================== Internal Block Operations ======================
    size_t insertBlock(Block *block);

    void updateBlock(Block *block);

    void deleteBlock(size_t pos);

    void unlinkBlock(Block *block);

    Block *findBlock(const std::string &plainPath, bool isFile) const;

    Block *findParent(const std::string &plainPath) const;

    size_t ensureDirChain(const std::string &plainPath);

    size_t createFileBlock(const std::string &plainName, const char *encData,
                           size_t encSize, size_t parentPos);

    std::pair<std::unique_ptr<char[]>, size_t> readFileData(Block *block) const;

    // ====================== Walk Implementation ======================
    void walkIterative(size_t startPos, const std::string &basePath, WalkCallback callback);

    // ====================== Export Implementation ======================
    void exportIterative(size_t startPos, const std::string &basePath);

    void exportSingleFile(Block *block, const std::string &destPath);

    // ====================== Filesystem Scanner ======================
    void scanFilesystem(const std::string &fsPath, const std::string &internalPlainPath);

    // ====================== Logging Implementation ======================
    void logOperation(const std::string &operation, const std::string &details = "");
};

#endif // INODE_H
