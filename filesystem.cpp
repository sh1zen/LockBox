#include "filesystem.h"

#include <fstream>
#include <algorithm>
#include <sys/stat.h>

#ifdef _WIN32
    #include <io.h>
    #include <direct.h>
    #include <windows.h>
    #define PATH_MAX 260
    #define getcwd _getcwd
    #define mkdir(path, mode) _mkdir(path)
    #define rmdir _rmdir
    #define access _access
    #define F_OK 0

    #ifndef S_ISREG
        #define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
    #endif
    #ifndef S_ISDIR
        #define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
    #endif
#else
    #include <dirent.h>
    #include <unistd.h>
    #include <climits>
#endif

// ====================== Win32 Dirent Implementation ======================

#ifdef _WIN32
struct dirent {
    char d_name[MAX_PATH];
};

struct DIR {
    HANDLE hFind;
    WIN32_FIND_DATAW findData;
    struct dirent entry;
    bool first;
    bool done;
};

static DIR *opendir(const char *path) {
    std::string searchPath = path;
    if (searchPath.empty()) searchPath = ".";
    if (searchPath.back() == '/' || searchPath.back() == '\\')
        searchPath += "*";
    else
        searchPath += "/*";

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, searchPath.c_str(), -1, nullptr, 0);
    std::wstring wSearchPath(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, searchPath.c_str(), -1, &wSearchPath[0], size_needed);

    DIR *dir = new DIR;
    dir->hFind = FindFirstFileW(wSearchPath.c_str(), &dir->findData);
    if (dir->hFind == INVALID_HANDLE_VALUE) {
        delete dir;
        return nullptr;
    }
    dir->first = true;
    dir->done = false;
    return dir;
}

static struct dirent *readdir(DIR *dir) {
    if (dir->done) return nullptr;

    if (!dir->first) {
        if (!FindNextFileW(dir->hFind, &dir->findData)) {
            dir->done = true;
            return nullptr;
        }
    } else {
        dir->first = false;
    }

    WideCharToMultiByte(CP_UTF8, 0, dir->findData.cFileName, -1, dir->entry.d_name, MAX_PATH, nullptr, nullptr);
    return &dir->entry;
}

static int closedir(DIR *dir) {
    if (dir) {
        FindClose(dir->hFind);
        delete dir;
    }
    return 0;
}
#endif

// ====================== File I/O ======================

std::pair<size_t, std::vector<char>> Filesystem::readFile(const std::string &path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
        throw std::runtime_error("Cannot open file: " + path);

    auto size = static_cast<size_t>(file.tellg());
    if (size == 0)
        return {0, {}};

    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);

    if (!file.read(buffer.data(), static_cast<std::streamsize>(size)))
        throw std::runtime_error("Cannot read file: " + path);

    return {size, std::move(buffer)};
}

bool Filesystem::writeFile(const std::string &path, const char *data, size_t length) {
    if (!data) return false;

    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) return false;

    file.write(data, static_cast<std::streamsize>(length));
    return file.good();
}

bool Filesystem::writeFile(const std::string &path, const std::vector<char> &data) {
    return writeFile(path, data.data(), data.size());
}

bool Filesystem::writeFile(const std::string &path, const std::string &data) {
    return writeFile(path, data.data(), data.size());
}

bool Filesystem::appendFile(const std::string &path, const char *data, size_t length) {
    if (!data) return false;

    std::ofstream file(path, std::ios::binary | std::ios::app);
    if (!file) return false;

    file.write(data, static_cast<std::streamsize>(length));
    return file.good();
}

// ====================== Path Operations ======================

std::string Filesystem::getCurrentDir() {
    char buf[PATH_MAX];
    if (getcwd(buf, PATH_MAX) == nullptr)
        return "";

    std::string path(buf);
    fixPathSeparators(path);

    if (!path.empty() && path.back() != '/')
        path += '/';

    return path;
}

std::string Filesystem::getParentDir(const std::string &path) {
    if (path.empty()) return "";

    std::string normalized = path;
    // Rimuovi trailing slash
    while (normalized.size() > 1 && (normalized.back() == '/' || normalized.back() == '\\'))
        normalized.pop_back();

    size_t pos = normalized.find_last_of("/\\");
    if (pos == std::string::npos) return "";
    if (pos == 0) return "/";

    return normalized.substr(0, pos);
}

std::string Filesystem::getFilename(const std::string &path) {
    if (path.empty()) return "";

    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return path;

    return path.substr(pos + 1);
}

std::string Filesystem::getBasename(const std::string &path) {
    std::string filename = getFilename(path);
    size_t pos = filename.find_last_of('.');

    if (pos == std::string::npos || pos == 0)
        return filename;

    return filename.substr(0, pos);
}

std::string Filesystem::getExtension(const std::string &path) {
    std::string filename = getFilename(path);
    size_t pos = filename.find_last_of('.');

    if (pos == std::string::npos || pos == filename.length() - 1)
        return "";

    return filename.substr(pos + 1);
}

std::string Filesystem::removeExtension(const std::string &path) {
    size_t pos = path.find_last_of('.');
    size_t slashPos = path.find_last_of("/\\");

    // Assicurati che il punto sia nel nome file, non nel percorso
    if (pos == std::string::npos || (slashPos != std::string::npos && pos < slashPos))
        return path;

    return path.substr(0, pos);
}

std::string Filesystem::removeFilename(const std::string &path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return "";

    return path.substr(0, pos);
}

std::string Filesystem::joinPath(const std::string &base, const std::string &name) {
    if (base.empty()) return name;
    if (name.empty()) return base;

    std::string result = base;

    // Rimuovi trailing slash da base
    while (!result.empty() && (result.back() == '/' || result.back() == '\\'))
        result.pop_back();

    // Rimuovi leading slash da name
    std::string cleanName = name;
    while (!cleanName.empty() && (cleanName.front() == '/' || cleanName.front() == '\\'))
        cleanName = cleanName.substr(1);

    return result + "/" + cleanName;
}

std::string Filesystem::normalizePath(const std::string &path) {
    if (path.empty()) return "";

    std::string result = path;
    fixPathSeparators(result);

    // Rimuovi doppi slash
    std::string cleaned;
    bool lastWasSlash = false;
    for (char c : result) {
        if (c == '/') {
            if (!lastWasSlash) {
                cleaned += c;
                lastWasSlash = true;
            }
        } else {
            cleaned += c;
            lastWasSlash = false;
        }
    }

    // Rimuovi trailing slash (eccetto per root)
    while (cleaned.size() > 1 && cleaned.back() == '/')
        cleaned.pop_back();

    return cleaned;
}

unsigned int Filesystem::getPathDepth(const std::string &path) {
    if (path.empty()) return 0;

    unsigned int depth = 0;
    for (size_t i = 1; i < path.length(); i++) {
        if (path[i] == '/' || path[i] == '\\')
            depth++;
    }
    return depth;
}

// ====================== File/Directory Checks ======================

bool Filesystem::exists(const std::string &path) {
    return access(path.c_str(), F_OK) != -1;
}

bool Filesystem::isFile(const std::string &path) {
    struct stat s{};
    if (stat(path.c_str(), &s) != 0) return false;
    return S_ISREG(s.st_mode);
}

bool Filesystem::isDirectory(const std::string &path) {
    struct stat s{};
    if (stat(path.c_str(), &s) != 0) return false;
    return S_ISDIR(s.st_mode);
}

size_t Filesystem::getFileSize(const std::string &path) {
    struct stat s{};
    if (stat(path.c_str(), &s) != 0) return 0;
    return static_cast<size_t>(s.st_size);
}

// ====================== Directory Operations ======================

bool Filesystem::createDirectory(const std::string &path, bool recursive) {
    if (path.empty()) return false;
    if (isDirectory(path)) return true;

    if (recursive) {
        std::string parent = getParentDir(path);
        if (!parent.empty() && !isDirectory(parent)) {
            if (!createDirectory(parent, true))
                return false;
        }
    }

    return mkdir(path.c_str(), 0777) == 0;
}

bool Filesystem::removeFile(const std::string &path) {
    if (!isFile(path)) return false;
    return std::remove(path.c_str()) == 0;
}

bool Filesystem::removeDirectory(const std::string &path, bool recursive) {
    if (!isDirectory(path)) return false;

    if (recursive) {
        auto entries = listDirectory(path);
        for (const auto &entry : entries) {
            std::string fullPath = joinPath(path, entry.name);
            if (entry.isDirectory) {
                if (!removeDirectory(fullPath, true))
                    return false;
            } else {
                if (!removeFile(fullPath))
                    return false;
            }
        }
    }

    return rmdir(path.c_str()) == 0;
}

std::vector<Filesystem::DirEntry> Filesystem::listDirectory(const std::string &path) {
    std::vector<DirEntry> entries;

    DIR *dir = opendir(path.c_str());
    if (!dir) return entries;

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;

        if (name == "." || name == "..")
            continue;

        std::string fullPath = joinPath(path, name);

        DirEntry dirEntry;
        dirEntry.name = name;
        dirEntry.isDirectory = isDirectory(fullPath);
        dirEntry.size = dirEntry.isDirectory ? 0 : getFileSize(fullPath);

        entries.push_back(std::move(dirEntry));
    }

    closedir(dir);
    return entries;
}

// ====================== Utilities ======================

void Filesystem::fixPathSeparators(std::string &path) {
    std::replace(path.begin(), path.end(), '\\', '/');
}

std::string Filesystem::toAbsolutePath(const std::string &path) {
    if (path.empty()) return getCurrentDir();

    // Già assoluto?
    if (path[0] == '/' || (path.length() > 1 && path[1] == ':'))
        return normalizePath(path);

    return normalizePath(joinPath(getCurrentDir(), path));
}