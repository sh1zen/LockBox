#include <iostream>
#include <ctime>

#ifdef _WIN32
#define __MINGW_USE_STD_BYTE 0
#include <windows.h>
#endif

#include <io.h>
#include <fcntl.h>

#include "utility.h"

#include <OpenES/OES.h>
#include <iNode/iNode.h>

#include "defines.h"
#include "io_helpers.h"
#include "raw-layer.h"

using namespace std;

#define ANALISIS_SPACE 1000
#define ANALISIS_ENCODE 1


int main(int argc, char *argv[]) {

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    clock_t begin = clock();


    string str;

    OES *oes = new OES();
    OES *oes2 = new OES();

    oes->set_key((char *) "ctk_key");
    oes2->set_key((char *) "this is the ke2");

    oes->extendWKey(16);
    oes2->extendWKey(8);

    oes->load_data((void*)"abcdefghijklmnopqrstuvxyz", 25);
    oes2->load_data((void*)"abcdefghijklmnopqrstuvxyz", 25);

    oes->streamMode = true;
    oes2->streamMode = true;


    OES enc;
    OES dec;

    const char *key = "password123";
    enc.set_key((char*)key);
    dec.set_key((char*)key);

    enc.streamMode = true;
    dec.streamMode = true;

    // --- Dati da cifrare a chunk ---
    const char *chunks[] = {
        "Questo è",
        " un messaggio ",
        "di prova per CKE ",
        "in stream mode."
    };

    std::vector<std::pair<void*, size_t>> encryptedChunks;

    std::cout << "\n=== CIFRATURA STREAM ===\n";

    for (int i = 0; i < 4; i++) {
        std::cout << "\n--- CHUNK " << (i+1) << " ENC ---\n";

        enc.load_data((void*)chunks[i], strlen(chunks[i]));

        enc.enc_cke();

        auto [hexPtr, hexLen] = enc.exportBlock(enc.get_cipherBlock(), OES_EXPORT_HEX);
        if (hexPtr) {
            std::cout << "CIPHERTEXT HEX: " << (char*)hexPtr << "\n";
        }

        // Salviamo il blocco cifrato in RAW per decodifica
        auto raw = enc.exportBlock(enc.get_cipherBlock(), OES_EXPORT_RAW);
        encryptedChunks.push_back(raw);
    }


    std::cout << "\n\n=== DECIFRATURA STREAM ===\n";

    for (size_t i = 0; i < encryptedChunks.size(); i++) {
        std::cout << "\n--- CHUNK " << (i+1) << " DEC ---\n";

        auto &raw = encryptedChunks[i];


        dec.load_cipher_block(static_cast<m_block*>(raw.first), raw.second);

        dec.dec_cke();

        auto [txtPtr, txtLen] = dec.exportBlock(dec.get_plainBlock(), OES_EXPORT_CHAR);

        if (txtPtr) {
            std::cout << "PLAINTEXT: " << (char*)txtPtr << "\n";
        }
    }





    return 0;
/*

    OES *enc = new OES();
    OES *dec = new OES();
    char key[] = "cbc_key";
    // Dati più lunghi per avere più blocchi
    char data[] = "AAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBB CCCCCCCCCCCCCCCC";

    enc->set_key(key);
    dec->set_key(key);

    size_t blockSize = 4;

    m_block *iv1 = (m_block *) malloc(blockSize * sizeof(m_block));
    m_block *iv2 = (m_block *) malloc(blockSize * sizeof(m_block));
    for (size_t i = 0; i < blockSize; i++) {
        iv1[i] = 0xAAAAAAAA;
        iv2[i] = 0xAAAAAAAA;
    }

    enc->setIV(iv1, blockSize);
    enc->load_data(data, strlen(data));
    enc->enc_cbc();

    auto cipher = enc->exportBlock(enc->get_cipherBlock(), OES_EXPORT_RAW);

    // Decifra con IV sbagliato
    dec->setIV(iv2, blockSize);
    dec->load_cipher_block(static_cast<m_block*>(cipher.first), cipher.second);
    dec->dec_cbc();

    auto result = dec->get_data();

    // Stampa per debug
    printf("Original: %s\n", data);
    printf("Decrypted: ");
    for (size_t i = 0; i < result.second; i++) {
        char c = ((char*)result.first)[i];
        printf("%c", (c >= 32 && c < 127) ? c : '?');
    }
    printf("\n");

    // Il primo blocco DEVE essere corrotto
    // Ma i blocchi successivi dovrebbero essere OK
    bool firstBlockCorrupted = (memcmp(result.first, data, blockSize * sizeof(m_block)) != 0);




return firstBlockCorrupted;

/**/

   // mBlock_dump(oes->get_plainBlock()->data, oes->get_plainBlock()->len);

    oes->enc_cbc();
    oes2->enc_adv();
//    mBlock_dump(oes->get_cipherBlock()->data, oes->get_cipherBlock()->len);
    //mBlock_dump(oes2->get_cipherBlock()->data, oes2->get_cipherBlock()->len);


   // oes->resetStreamState();
    oes->dec_cbc();
    oes2->dec_adv();

    oes->dump(false);

    pair<void*, size_t> k = oes->get_data();

    char* buf = static_cast<char*>(k.first);
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
*//*

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

