#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <string>
#include <vector>
#include <utility>

class Filesystem {
public:
    // ====================== Directory Entry ======================
    struct DirEntry {
        std::string name;
        bool isDirectory;
        size_t size;

        DirEntry() : isDirectory(false), size(0) {
        }

        DirEntry(std::string n, bool dir, size_t s = 0)
            : name(std::move(n)), isDirectory(dir), size(s) {
        }
    };

    // ====================== File I/O ======================
    static std::pair<size_t, std::vector<char> > readFile(const std::string &path);

    static bool writeFile(const std::string &path, const char *data, size_t length);

    static bool writeFile(const std::string &path, const std::vector<char> &data);

    static bool writeFile(const std::string &path, const std::string &data);

    static bool appendFile(const std::string &path, const char *data, size_t length);

    // ====================== Path Operations ======================
    static std::string getCurrentDir();

    static std::string getParentDir(const std::string &path);

    static std::string getFilename(const std::string &path);

    static std::string getBasename(const std::string &path);

    static std::string getExtension(const std::string &path);

    static std::string removeExtension(const std::string &path);

    static std::string removeFilename(const std::string &path);

    static std::string joinPath(const std::string &base, const std::string &name);

    static std::string normalizePath(const std::string &path);

    static unsigned int getPathDepth(const std::string &path);

    // ====================== File/Directory Checks ======================
    static bool exists(const std::string &path);

    static bool isFile(const std::string &path);

    static bool isDirectory(const std::string &path);

    static size_t getFileSize(const std::string &path);

    // ====================== Directory Operations ======================
    static bool createDirectory(const std::string &path, bool recursive = false);

    static bool removeFile(const std::string &path);

    static bool removeDirectory(const std::string &path, bool recursive = false);

    static std::vector<DirEntry> listDirectory(const std::string &path);

    // ====================== Utilities ======================
    static void fixPathSeparators(std::string &path);

    static std::string toAbsolutePath(const std::string &path);
};

#endif // FILESYSTEM_H
