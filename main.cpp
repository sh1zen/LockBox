#include <iostream>
#include <ctime>

#ifdef _WIN32
#define __MINGW_USE_STD_BYTE 0
#include <windows.h>
#endif

#include <cmath>
#include <io.h>
#include <iomanip>
#include <map>

#include "utility.h"

#include <OpenES/OES.h>
#include <iNode/iNode.h>

#include "constants.h"
#include "hashing.h"
#include "io_helpers.h"
#include "key_management.h"
#include "prng.h"
#include "raw-layer.h"
#include "sphinix.h"

using namespace std;

#define ANALISIS_SPACE 1000
#define ANALISIS_ENCODE 1


int main(int argc, char *argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

  //  prng_tests::run_all();

    // return 0;

    string str;

    clock_t begin = clock();

    OES *enc = new OES();
    OES *dec = new OES();
    char key[] = "adv_stream_key";
    char data1[] = "First ADV block yes!";
    char data2[] = "checking encriptation 0101!";

    enc->set_key(key);
    dec->set_key(key);

    enc->load_data_raw(data2, strlen(data2));

    enc->enc_cbc();

    enc->dump();

    dec->load_cipher_block(enc->get_cipherBlock());

    dec->dec_cbc();

    dec->dump();

    cout << endl << double(clock() - begin) / CLOCKS_PER_SEC << "s" << endl;

    return 0;


    enc->load_data_raw(data2, strlen(data2));
    enc->enc_ctr();
    MBLOCK *cipher1 = enc->get_cipherBlock();


    // Decrypt chunks
    dec->load_cipher_block(cipher1, false);
    dec->dec_ctr();
    dec->dump(true);



    return 0;


    OES *oes = new OES();


    oes->set_key("cycle_key");
    auto uuu = (char *) "cycling data through multiple rounds\0";
    oes->load_data_raw(uuu, strlen(uuu));

    oes->enc_adv();

    oes->resetStreamState();
    oes->dec_adv();


    oes->dump(false);

    pair<void *, size_t> k = oes->get_data();

    char *buf = static_cast<char *>(k.first);
    size_t len = k.second;

    cout << "\nContenuto come stringa (" << len << " bytes):\n";

    for (size_t i = 0; i < len; ++i) {
        cout << buf[i];
    }

    cout << "\n\n";

    oes->dump(false);

    return 0;

    if (argc < 2) {
        handle_error("Missing second parameter.", 1);
    }

    //if it's a directory ask if to encrypt it or create a lockbox
    // directory encryption: recursive by substituting files with encrypted one's
    string file_path = string(R"(D:\github\LockBox\test)");

    fix_path_escape(file_path);

    //cout << "Insert iNode password: >> ";

    //  string password = get_password();

    //cout << endl << endl;

    //oes->set_key(const_cast<char *>(password.c_str()));

    // oes->extendWKey(10);


    std::cout << "\n=== Example 3: Manual File Operations ===\n" << std::endl;

    /*
        iNode node("C:/Users/andre/Desktop/test/archive.sc", nullptr);
        node.display();

        std::cout << "All entries:" << std::endl;
        node.walk([](Block* block, const std::string& path, iNode* n) {
            std::cout << (block->isFile ? "  FILE: " : "  DIR:  ") << path << std::endl;
        });

        // Walk specific subdirectory
        std::cout << "\nEntries in 'documents':" << std::endl;
        node.walk("documents", [](Block* block, const std::string& path, iNode* n) {
            if (block->isFile) {
                std::cout << "  📄 " << path << " (" << block->size << " bytes)" << std::endl;
            }
        });

        // Count files by extension
        int txtCount = 0;
        node.walk([&txtCount](Block* block, const std::string& path, iNode* n) {
            if (block->isFile && path.ends_with(".txt")) {
                txtCount++;
            }
        });

        return 0;
    */ /*

    // Create new iNode
    iNode node("C:/Users/andre/Desktop/test/archive.sc", oes);

    // Add directories
    node.addDirectory("documents");
    node.addDirectory("documents/reports");
    node.addDirectory("images");

    // Add files
    const char* data1 = "This is a text file content";
    node.addFile("documents/readme.txt", data1, strlen(data1));

    const char* data2 = "Report content here...";
    node.addFile("documents/reports/quarterly.txt", data2, strlen(data2));

    // Check if file exists
    if (node.exists("documents/readme.txt", true)) {
        std::cout << "File exists!" << std::endl;
    }

    // Read file
    auto fileContent = node.readFile("documents/readme.txt");
    if (fileContent.first) {
        std::cout << "File content: " << std::string(fileContent.first, fileContent.second) << std::endl;
        free(fileContent.first);
    }

    // Update file
    const char* newData = "Updated content";
    node.updateFile("documents/readme.txt", newData, strlen(newData));

    cout << node.countSubdirs("/") << endl;

    // Display structure
    node.display();

    // Save
    node.save();

    node.exportTo("C:/Users/andre/Desktop/testt");


    cout << endl << double(clock() - begin) / CLOCKS_PER_SEC << "s" << endl;
*/
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
save(fd);
*/
