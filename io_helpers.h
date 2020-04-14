#pragma once
#ifndef LOCKBOX_IO_HELPERS_H
#define LOCKBOX_IO_HELPERS_H

// Minimal, portable includes for a header
#include <utility>    // std::pair
#include <string>     // std::string

#ifdef _WIN32
  #include <direct.h>
#else
  #include <unistd.h>
  #include <sys/stat.h>
#endif

// Provide S_ISDIR / S_ISREG only if not provided by platform headers
#ifndef S_ISDIR
  #define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#endif

#ifndef S_ISREG
  #define S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#endif

#define PATH_SIZE 512

// Forward declarations / prototypes
// I/O
std::pair<size_t, char*> read_file(const char *filepath);
bool write_file(const char *filepath, const char *src, size_t length);

// Filesystem utilities
unsigned int get_path_level(const char *path);

// Return parent directory (does not modify input)
std::string getParentDir(const std::string &path);

// Current working directory (string ends with '/')
std::string GetCurrentDir();

// Return the path without filename (same as dirname)
std::string remove_filename(const std::string &path);

// Convert backslashes to slashes in-place
void fix_path_escape(std::string &filepath);

// Return filename portion (after last slash/backslash)
std::string filename(const std::string &path);

// Return basename (path without trailing filename)
std::string basename(const std::string &path);

// Remove file extension (everything after last '.')
std::string remove_extension(const std::string &filename);

// Return file extension (without the dot). Empty if none.
std::string file_extension(const std::string &filepath);

// Create directory. If recursive==true create parent directories as needed.
bool makePath(const std::string &path, bool recursive);

// Type-checking helpers
bool is_file(const char *filename);
bool is_dir(const char *filename);

// Existence checks
bool file_exists(const char *path);
bool dir_exists(const char *path);

#endif // LOCKBOX_IO_HELPERS_H
