#include <sys/stat.h>
#include <fcntl.h>

#include "io_helpers.h"
#include "utility.h"
#include "mman.h"


size_t getFileSize(int fd) {
    return lseek(fd, 0, SEEK_END);
}

bool write_file(const char *filepath, char *src, size_t length) {
    char *dst;

    int fd = open(filepath, O_RDWR | O_CREAT | O_TRUNC, 0x0777);

    if (fd == -1)
        handle_error("open", 255);

    dst = (char *) mmap(nullptr, length, PROT_WRITE, MAP_FILE, fd, 0);

    if (dst == MAP_FAILED)
        handle_error("mmap", EXIT_FAILURE);

    memcpy(dst, src, length);

    munmap(dst, length);

    msync(dst, length, MS_SYNC);

    close(fd);

    return true;
}

pair<size_t, char *> read_file(const char *filepath) {
    char *src, *dst;
    int fd;
    size_t length;

    fd = open(filepath, O_RDONLY);

    if (fd == -1)
        handle_error("open", 255);

    length = getFileSize(fd);

    if (length == 0)
        return make_pair(0, nullptr);

    src = (char *) mmap(nullptr, length, PROT_READ, MAP_FILE, fd, 0);

    if (src == MAP_FAILED)
        handle_error("mmap", EXIT_FAILURE);

    dst = (char *) malloc(sizeof(char) * length);

    if (!dst)
        handle_error("malloc", EXIT_FAILURE);

    memcpy(dst, src, length);

    //msync(dst, length, MS_SYNC);

    munmap(src, length);

    close(fd);

    return make_pair(length, dst);
}


/**************************************************
 *                                                *
 * Set of utility function for system file access *
 *                                                *
 **************************************************/


unsigned int get_path_level(const char *path) {

    unsigned int i, level = 0;

    for (i = 1; i < strlen(path); i++)
        if (path[i] == '/' or path[i] == '\\')
            level++;

    return level;
}


string getParentDir(string &path) {
    return path.substr(0, path.find_last_of("/\\"));
}

bool makePath(string path, bool recursive) {

    if (is_dir(path.c_str()))
        return true;

    if (recursive) {
        return  makePath(getParentDir(path), recursive) * mkdir(path.c_str()) == 0;
    } else
        return mkdir(path.c_str()) == 0;
}


string GetCurrentDir() {

    char buf[PATH_SIZE];

    GetCurrentDirectoryA(PATH_SIZE, buf);

    string current_path = string(buf) + "/";

    fix_path_escape(current_path);

    return current_path;
}

string remove_filename(const string &path) {
    return path.substr(0, path.find_last_of("\\/"));
}

void fix_path_escape(string &filepath) {
    replace(filepath.begin(), filepath.end(), '\\', '/');
}

string filename(const string &path) {
    return path.substr(path.find_last_of("/\\") + 1);
}

string basename(const string &path) {
    return path.substr(0, path.find_last_of("/\\"));
}


string remove_extension(const string &filename) {
    size_t lastdot = filename.find_last_of('.');

    if (lastdot == string::npos)
        return filename;

    return filename.substr(0, lastdot);
}

string file_extenson(const string &filepath) {

    string extension = filename(filepath);
    return extension.substr(extension.find_last_of('.') + 1);
}


bool is_file(const char *filename) {
    struct stat status{};
    if (stat(filename, &status) != 0) {
        // path does not exist
        return false;
    }
    // Tests whether existing path is a regular file
    return S_ISREG(status.st_mode);
}

bool is_dir(const char *filename) {

    struct stat status{};

    if (stat(filename, &status) != 0) {
        // path does not exist
        return false;
    }

    // Tests whether existing path is a Dir
    return S_ISDIR(status.st_mode);
}

bool file_exists(char *path) {
    return access(path, F_OK) != -1;
}

bool dir_exists(char *path) {
    return is_dir(path);
}

