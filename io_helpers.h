#ifndef LOCKBOX_IO_HELPERS_H
#define LOCKBOX_IO_HELPERS_H

#include <bits/stdc++.h> //support for pair tuple

#ifdef WINDOWS
#include <direct.h>
#else
#include <unistd.h>
#endif

#ifndef S_ISDIR
#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#endif

#ifndef S_ISREG
#define S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#endif

#define PATH_SIZE 512

using namespace std;
/**
 * Input - Output
 */

pair<size_t, char *> read_file(const char *filepath);

bool write_file(const char *filepath, char *src, size_t length);

/**
 * Filesystem utility
 */

unsigned int get_path_level(const char *path);

string getParentDir(string &path);

string GetCurrentDir();

string remove_filename(const string& path);

void fix_path_escape(string &filepath);

string filename(const string& path);

string basename(const string& path);

string remove_extension(const string& filename);

string file_extenson(const string& filepath);

bool makePath(string path, bool recursive);

bool is_file(const char *filename) ;

bool is_dir(const char *filename) ;

bool file_exists(char *path) ;

bool dir_exists(char *path) ;



#endif //LOCKBOX_IO_HELPERS_H
