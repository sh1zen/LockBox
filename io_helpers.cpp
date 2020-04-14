#include "io_helpers.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <stdexcept>

#ifdef _WIN32
#define __MINGW_USE_STD_BYTE 0
#include <windows.h>
#endif

#include <unistd.h>

#include "mman.h"
#include "utility.h"


// --------------------------------------------------------------
//  FILE I/O (memory-mapped)
// --------------------------------------------------------------

size_t getFileSize(int fd) {
    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0)
        handle_error("lseek", 255);

    if (lseek(fd, 0, SEEK_SET) < 0)
        handle_error("lseek-reset", 255);

    return static_cast<size_t>(size);
}


std::pair<size_t, char*> read_file(const char *filepath) {
    int fd = open(filepath, O_RDONLY);
    if (fd == -1)
        handle_error("open", 255);

    size_t length = getFileSize(fd);
    if (length == 0) {
        close(fd);
        return std::make_pair(0, nullptr);
    }

    char *src = (char*) mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (src == MAP_FAILED)
        handle_error("mmap", EXIT_FAILURE);

    char *dst = (char*) malloc(length);
    if (!dst)
        handle_error("malloc", EXIT_FAILURE);

    memcpy(dst, src, length);

    munmap(src, length);
    close(fd);

    return std::make_pair(length, dst);
}


bool write_file(const char *filepath, const char *src, size_t length) {
    int fd = open(filepath, O_RDWR | O_CREAT | O_TRUNC, 0777);
    if (fd == -1)
        handle_error("open", 255);

    // Resize file for mmap
    if (ftruncate(fd, length) != 0)
        handle_error("ftruncate", 255);

    char *dst = (char*) mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
    if (dst == MAP_FAILED)
        handle_error("mmap", EXIT_FAILURE);

    memcpy(dst, src, length);

    if (msync(dst, length, MS_SYNC) != 0)
        handle_error("msync", EXIT_FAILURE);

    munmap(dst, length);
    close(fd);

    return true;
}



// --------------------------------------------------------------
//  PATH / FILESYSTEM UTILITIES
// --------------------------------------------------------------

unsigned int get_path_level(const char *path) {
    unsigned int level = 0;
    size_t len = strlen(path);
    for (size_t i = 1; i < len; i++)
        if (path[i] == '/' || path[i] == '\\')
            level++;
    return level;
}


std::string getParentDir(const std::string &path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return "";
    return path.substr(0, pos);
}


std::string GetCurrentDir() {
    char buf[PATH_SIZE];

#ifdef _WIN32
    GetCurrentDirectoryA(PATH_SIZE, buf);
#else
    getcwd(buf, PATH_SIZE);
#endif

    std::string current_path(buf);
    current_path += "/";
    fix_path_escape(current_path);

    return current_path;
}


std::string remove_filename(const std::string &path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return path;
    return path.substr(0, pos);
}


void fix_path_escape(std::string &filepath) {
    std::replace(filepath.begin(), filepath.end(), '\\', '/');
}


std::string filename(const std::string &path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}


std::string basename(const std::string &path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return "";
    return path.substr(0, pos);
}


std::string remove_extension(const std::string &name) {
    size_t pos = name.find_last_of('.');
    if (pos == std::string::npos) return name;
    return name.substr(0, pos);
}


std::string file_extension(const std::string &filepath) {
    std::string name = filename(filepath);
    size_t pos = name.find_last_of('.');
    if (pos == std::string::npos) return "";
    return name.substr(pos + 1);
}


bool makePath(const std::string &path, bool recursive) {
    if (path.empty())
        return false;

    if (is_dir(path.c_str()))
        return true;

    if (recursive) {
        std::string parent = getParentDir(path);
        if (!parent.empty() && !is_dir(parent.c_str())) {
            if (!makePath(parent, true))
                return false;
        }
    }

#ifdef _WIN32
    return _mkdir(path.c_str()) == 0;
#else
    return mkdir(path.c_str(), 0777) == 0;
#endif
}


bool is_file(const char *filename) {
    struct stat s{};
    return stat(filename, &s) == 0 && S_ISREG(s.st_mode);
}


bool is_dir(const char *filename) {
    struct stat s{};
    return stat(filename, &s) == 0 && S_ISDIR(s.st_mode);
}


bool file_exists(const char *path) {
    return access(path, F_OK) != -1;
}


bool dir_exists(const char *path) {
    return is_dir(path);
}
