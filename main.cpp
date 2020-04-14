#include <iostream>
#include <ctime>

#include "utility.h"
#include "crypto.h"
#include "iNode/iNode.h"
#include "io_helpers.h"

using namespace std;

int main(int argc, char *argv[]) {

    if (argc < 2)
        handle_error("Missing second parameter.", 1);

    clock_t begin = clock();

    string file_path = string(argv[1]);

    fix_path_escape(file_path);

    iNode st;

    cout << "Insert LockBox password (max CRYPTO_HASH_DIM) >> ";

    string password = get_password(CRYPTO_HASH_DIM);

    char *cipher = make_hash(password.c_str(), password.size());

    cout << endl << endl;

    if (is_lockbox(file_path)) {
        st = inode_load(file_path, cipher);
        inode_build(st, "root");
    } else {
        //system("del /f lockbox.sc");
        st = inode_init(file_path, cipher);
    }

    inode_close(st);

    inode_display(st);

    cout << endl << double(clock() - begin) / CLOCKS_PER_SEC << "s" << endl;

    wait(0);

    return 0;
}




/*
int fd = open("test_file", O_RDWR | O_CREAT, (mode_t)0600);
const char *text = "hello";
size_t textsize = strlen(text) + 1;
lseek(fd, textsize-1, SEEK_SET);
write(fd, "", 1);
char *map = (char*)mmap(0, textsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
memcpy(map, text, strlen(text));
msync(map, textsize, MS_SYNC);
munmap(map, textsize);
close(fd);
*/

