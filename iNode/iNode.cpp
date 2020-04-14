#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
//#include <typeinfo>

#include "mman.h"
#include "iNode.h"
#include "utility.h"
#include "io_helpers.h"
#include "crypto.h"

#define _DEBUG_ 1

#include <sys/types.h>

#include <sys/stat.h>

#include <fcntl.h>

using namespace std;

struct inode_st {
    int lockbox = -1;
    char cipher[CRYPTO_HASH_DIM]{};
    off64_t root = -1;
    u_int64 cipher_check = 0;
};

typedef struct block {
    char name[PATH_SIZE]{};
    bool isFile = false;

    u_int files_n = 0;
    u_int folders_n = 0;

    // position of the first subdir block
    off64_t subdir_pos = 0;
    off64_t parent = 0;

    // position of current file or position of the first file block
    off64_t data_pos = 0;
    size_t size = 0;

    // position of the current block
    off64_t current = 0;

    // position of the next file or the next folder on the same level
    off64_t next = 0;
    off64_t previous = 0;

    u_int level = 0;
} *Block;

typedef void (*callback)(Block, string &, iNode);

void unset_block(Block b) {
    if (b != nullptr)
        free(b);
}

void reset_block(Block block) {

    memset(block->name, '\0', PATH_SIZE);

    block->isFile = false;

    block->files_n = 0;
    block->folders_n = 0;

    block->subdir_pos = 0;
    block->parent = 0;

    block->data_pos = 0;
    block->size = 0;

    block->current = 0;

    block->next = 0;
    block->previous = 0;

    block->level = 0;
}

Block initialize_block() {

    auto block = (Block) malloc(sizeof(struct block));

    reset_block(block);

    return block;
}

size_t get_lockbox_size(int box) {
    if (box <= 0)
        return 0;
    return lseek64(box, 0, SEEK_END);
}

void inode_copy(Block dst, Block src) {
    memcpy(dst, src, sizeof(struct block));
}

Block inode_clone(Block src) {
    Block block = initialize_block();

    if (src != nullptr)
        inode_copy(block, src);

    return block;
}

// write at the end
off64_t inode_insert(int box, void *buf, size_t size) {

    if (box <= 0)
        return 0;

    off64_t pos = get_lockbox_size(box);

    // mmap the output file
    char *dst = (char *) mmap(nullptr, pos + size, PROT_WRITE, MAP_FILE, box, 0);

    if (dst == MAP_FAILED)
        return 0;

    memcpy(dst + pos, buf, size);

    msync(dst, size + pos, MS_SYNC);

    munmap(dst, size + pos);

    return pos;
}

// write in a specific position
bool inode_write(int box, void *buf, off64_t pos, size_t size) {

    if (box <= 0)
        return false;
    /*
    lseek64(box, pos, SEEK_SET);
    return write(box, buf, size) > 0;
    */

    off64_t length = get_lockbox_size(box);

    if (pos + size > length)
        return false;

    char *mapped_memory = (char *) mmap(nullptr, length, PROT_WRITE, MAP_FILE, box, 0);

    if (mapped_memory == MAP_FAILED)
        return false;

    memcpy(mapped_memory + pos, buf, size);

    munmap(mapped_memory, length);

    return true;
}

bool inode_read(int box, off64_t offset, void *buf, size_t size) {

    if (box <= 0 or buf == nullptr)
        return false;

    off64_t length = get_lockbox_size(box);

    char *mapped_memory = (char *) mmap(nullptr, length, PROT_READ, MAP_FILE, box, 0);

    if (mapped_memory == MAP_FAILED)
        return false;

    memcpy(buf, mapped_memory + offset, size);

    munmap(mapped_memory, length);

    return true;
}

bool inode_read_block(int box, off64_t offset, Block block) {

    if (box < 0 or offset <= 0)
        return false;

    return inode_read(box, offset, (void *) block, sizeof(struct block));
}


/**
 * Insert a new block and return its position
 */
off64_t inode_insert_block(int box, Block block) {
    return inode_insert(box, block, sizeof(struct block));
}

/**
 * Update a specific block
 */
bool inode_update_block(int box, Block block) {
    return inode_write(box, block, block->current, sizeof(struct block));
}

/**
 * Replace a block in a specific position
 * @todo verify memory before replace
 */
bool inode_replace_block(int box, off64_t pos, Block block) {
    // code useful typeid(block).name();
    return inode_write(box, block, pos, sizeof(struct block));
}


/**
 * usefull function to debug
 */
void inode_debug_blockInfo(Block block, int lockbox) {

    cout << endl << "=====   DEBUG BLOCK  =====" << endl;
    cout << "Name: " << block->name << endl;

    if (lockbox > 0) {
        auto parent = initialize_block();

        inode_read_block(lockbox, block->parent, parent);
        cout << "Parent name: " << parent->name << endl;
    }

    cout << "isFile: " << block->isFile << endl;
    cout << "Data pos: " << block->data_pos << endl;
    cout << "Data size: " << block->size << endl;

    cout << "==========================" << endl << endl;
}

// return the the found block if exists
Block inode_block_exist(iNode st, string &filepath, bool isFile) {

    // fix: prevent error due to inconsistent root position
    if (st->root <= 0)
        return nullptr;

    bool match = true;
    auto block = initialize_block();

    if (!inode_read_block(st->lockbox, st->root, block))
        return nullptr;

    if (!inode_read_block(st->lockbox, block->subdir_pos, block))
        return nullptr;

    istringstream strTokenizer(filepath);
    string token;

    while (getline(strTokenizer, token, '/') and !block->isFile and match) {

        match = false;

        // iterate over all sub directories, update c_offset to the valid one
        do {

            if (strcmp(block->name, token.c_str()) == 0) {
                match = true;
                continue;
            }

        } while (inode_read_block(st->lockbox, block->next, block));

        if (match and block->subdir_pos != 0) {

            if (!inode_read_block(st->lockbox, block->subdir_pos, block))
                handle_error("reading lockbox", 56);
        }
    }

    if (!match) {
        unset_block(block);
        return nullptr;
    }

    if (!isFile) {
        return block;
    }

    off64_t c_offset = block->data_pos;

    // iterate over all files in the current directory
    while (block->next != 0) {

        if (!inode_read_block(st->lockbox, c_offset, block))
            handle_error("reading lockbox", 56);

        if (strcmp(block->name, filename(filepath).c_str()) == 0) {
            return block;
        }

        c_offset = block->next;
    }

    unset_block(block);

    return nullptr;
}

// return the position of the latest found block
pair<u_int, Block> inode_descending(iNode st, string &filepath, bool look4File) {

    // fix: prevent error due to inconsistent root position
    if (st->root <= 0)
        return make_pair(0, nullptr);

    bool match = true;
    u_int level = 0;

    auto block = initialize_block();

    if (!inode_read_block(st->lockbox, st->root, block)) {
        unset_block(block);
        return make_pair(0, nullptr);
    }

    if (filepath.empty())
        return make_pair(0, block);

    // first usable block (root is reserved)
    if (!inode_read_block(st->lockbox, block->subdir_pos, block)) {

        // search for files
        if (block->data_pos != 0) {
            inode_read_block(st->lockbox, block->data_pos, block);
            return make_pair(0, block);
        }

        unset_block(block);
        return make_pair(0, nullptr);
    }

    auto prev_block = initialize_block();

    inode_copy(prev_block, block);

    istringstream strTokenizer(filepath);
    string token;

    while (getline(strTokenizer, token, '/') and match) {

        match = false;

        // iterate over all sub directories, update c_offset to the valid one
        do {

            if (strcmp(block->name, token.c_str()) == 0) {
                inode_copy(prev_block, block);
                match = true;
                continue;
            }

        } while (inode_read_block(st->lockbox, block->next, block));


        if (match) {
            level++;
            inode_read_block(st->lockbox, block->subdir_pos, block);
        }
    }

    off64_t c_offset;

    if (look4File) {
        c_offset = block->data_pos;

        // iterate over all files in the current directory
        while (block->next != 0) {

            if (!inode_read_block(st->lockbox, c_offset, block))
                handle_error("reading lockbox", 56);

            if (strcmp(block->name, filename(filepath).c_str()) == 0) {
                unset_block(prev_block);
                return make_pair(level, block);
            }

            c_offset = block->next;
        }
    }

    unset_block(block);

    return make_pair(level, prev_block);
}

Block inode_getBlock_byPath(iNode st, string &filepath) {
    pair<u_int, Block> p = inode_descending(st, filepath, false);

    return p.second;
}

// return the position of the file or of the directory block
off64_t inode_exist(iNode st, string &filepath, bool file) {
    off64_t pos;

    Block block = inode_block_exist(st, filepath, file);

    if (block == nullptr)
        return 0;

    if (file) {
        pos = block->data_pos;
    } else {
        pos = block->current;
    }

    unset_block(block);

    return pos;
}

// todo fix cout for all subdirs
u_int inode_count_subdirs(iNode st, Block block) {
    u_int folders = 0;

    auto subDir = initialize_block();

    inode_read_block(st->lockbox, block->subdir_pos, subDir);

    do {
        folders += subDir->folders_n;
    } while (inode_read_block(st->lockbox, subDir->subdir_pos, subDir));

    return folders;
}

// todo fix cout for all files
u_int inode_count_files(iNode st, Block block) {
    u_int files = 0;

    auto file = initialize_block();

    inode_read_block(st->lockbox, block->data_pos, file);

    do {
        files += file->files_n;
    } while (inode_read_block(st->lockbox, file->next, file));

    return files;
}

// return the position of the latest directory added
off64_t inode_create_path(iNode st, string &filepath) {

    Block dirBlock;
    auto tmpBlock = initialize_block();
    auto parentBlock = initialize_block();

    u_int found_level = 0, level = 0;

    pair<u_int, Block> p = inode_descending(st, filepath, false);

    off64_t parentPos;

    if (p.first > 0 and p.second != nullptr) {
        parentPos = p.second->current;
        found_level = p.first;
    } else {
        parentPos = st->root;
    }

    inode_read_block(st->lockbox, parentPos, parentBlock);

    // initialize, fix due to already present path
    dirBlock = inode_clone(parentBlock);

    if (p.second != nullptr)
        unset_block(p.second);

    istringstream strTokenizer(filepath);
    string token;

    while (getline(strTokenizer, token, '/')) {

        if (++level > found_level) {

            reset_block(dirBlock);

            dirBlock->isFile = false;
            strcpy(dirBlock->name, token.c_str());
            dirBlock->parent = parentBlock->current;
            dirBlock->level = level;

            dirBlock->current = inode_insert_block(st->lockbox, dirBlock);

            if (parentBlock->subdir_pos != 0) {

                inode_read_block(st->lockbox, parentBlock->subdir_pos, tmpBlock);

                while (tmpBlock->next != 0) {

                    if (strcmp(token.c_str(), tmpBlock->name) == 0)
                        break;

                    inode_read_block(st->lockbox, tmpBlock->next, tmpBlock);
                }

                // update the block chain: dirBlock level
                tmpBlock->next = dirBlock->current;
                dirBlock->previous = tmpBlock->current;
                inode_update_block(st->lockbox, tmpBlock);
            }

            // update the current block data
            inode_update_block(st->lockbox, dirBlock);

            // update parent subdir_pos
            if (parentBlock->subdir_pos == 0) {
                parentBlock->subdir_pos = dirBlock->current;
            }

            parentBlock->folders_n++;
            // update the parent
            inode_update_block(st->lockbox, parentBlock);

            // make current block next parent
            inode_copy(parentBlock, dirBlock);
        }
    }

    parentPos = dirBlock->current;

    unset_block(dirBlock);
    unset_block(tmpBlock);

    return parentPos;
}

off64_t inode_create_file(iNode st, string &file_name, char *src, size_t file_size, off64_t parent) {

    if (parent <= 0)
        handle_error("inode_create_file :: invalid parent ", 0);

    auto fileBlock = initialize_block();
    auto tmpBlock = initialize_block();
    bool iterateFiles = true;
    off64_t fileBlock_pos = 0;

    // prev fill the block space
    fileBlock->current = inode_insert_block(st->lockbox, fileBlock);

    strcpy(fileBlock->name, file_name.c_str());

    fileBlock->parent = parent;
    fileBlock->isFile = true;
    fileBlock->next = 0;
    fileBlock->previous = 0;
    fileBlock->size = file_size;

    fileBlock->data_pos = inode_insert(st->lockbox, src, file_size);

    // work over parent Block
    inode_read_block(st->lockbox, parent, tmpBlock);
    tmpBlock->files_n++;

    fileBlock->level = tmpBlock->level + 1;

    if (tmpBlock->data_pos == 0) {
        tmpBlock->data_pos = fileBlock->current;
        iterateFiles = false;
    }

    // save the parent block
    inode_update_block(st->lockbox, tmpBlock);

    if (iterateFiles) {

        // search for the latest file and update the next value
        inode_read_block(st->lockbox, tmpBlock->data_pos, tmpBlock);

        while (tmpBlock->next != 0) {
            inode_read_block(st->lockbox, tmpBlock->next, tmpBlock);
        }

        tmpBlock->next = fileBlock->current;

        // set previous file position
        fileBlock->previous = tmpBlock->current;

        // save the previous block
        inode_update_block(st->lockbox, tmpBlock);
    }

    // re-save current block
    inode_update_block(st->lockbox, fileBlock);

    //save current block position
    fileBlock_pos = fileBlock->current;

    // free memory used
    unset_block(tmpBlock);
    unset_block(fileBlock);

    return fileBlock_pos;
}

off64_t inode_add_file(iNode st, string &filepath, char *src, size_t size) {

    off64_t pos = 0;

    string file_name = filename(filepath);
    string path_path = basename(filepath);

    if ((pos = inode_exist(st, filepath, true)) > 0)
        return pos;

    if (file_name == path_path)
        path_path = "";

    pos = inode_create_path(st, path_path);
    pos = inode_create_file(st, file_name, src, size, pos);

    return pos;
}

off64_t inode_add_directory(iNode st, string &filepath) {
    off64_t pos = 0;

    if ((pos = inode_exist(st, filepath, false)) > 0)
        return pos;

    pos = inode_create_path(st, filepath);

    return pos;
}

/****************************************************
 * Walkers functions (iNode, path)
 ****************************************************/

void path_walker(iNode st, string &path, string internalPath) {
    DIR *dp;
    struct dirent *dirp;
    struct stat filestat{};
    string filepath, inner_filepath;
    clock_t begin;

    // fix for direct file access
    if (is_file(path.c_str())) {

        pair<size_t, char *> p = read_file(path.c_str());

        encript(p.second, st->cipher, p.first);

        filepath = filename(path);

        inode_add_file(st, filepath, p.second, p.first);

        free(p.second);

        return;
    }

    dp = opendir(path.c_str());

    if (dp == nullptr) {
        handle_error("Error opening folder", 255);
    }

    while ((dirp = readdir(dp))) {

        if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
            continue;

        filepath = path + "/" + string(dirp->d_name);

        if (internalPath.empty())
            inner_filepath = string(dirp->d_name);
        else
            inner_filepath = internalPath + "/" + string(dirp->d_name);

        if (stat(filepath.c_str(), &filestat))
            continue;

        if (S_ISDIR(filestat.st_mode)) {
            cout << "Directory: " << filepath << endl;

            inode_add_directory(st, inner_filepath);

            path_walker(st, filepath, inner_filepath);
        } else {
            begin = clock();
            cout << "File: " << filepath;

            pair<size_t, char *> p = read_file(filepath.c_str());

            encript(p.second, st->cipher, p.first);

            inode_add_file(st, inner_filepath, p.second, p.first);

            free(p.second);

            cout << " " << double(clock() - begin) / CLOCKS_PER_SEC << "s" << endl;
        }
    }

    closedir(dp);
}

void inode_walker(iNode st, off64_t dirBlock_pos, int level, const string &tabspath, callback _callback) {

    if (dirBlock_pos == 0)
        return;

    string abspath, filepath;

    auto block = initialize_block();

    inode_read_block(st->lockbox, dirBlock_pos, block);

    if (block->isFile) {
        abspath = tabspath + string(block->name);

        if (_callback != nullptr)
            _callback(block, abspath, st);

        // iterate over all files
        if (block->next != 0)
            inode_walker(st, block->next, level, tabspath, _callback);

        return;
    }

    abspath = tabspath + string(block->name) + "/";

    if (_callback != nullptr)
        _callback(block, abspath, st);


    // recurse over subdir
    if (block->subdir_pos != 0)
        inode_walker(st, block->subdir_pos, level + 1, abspath, _callback);

    // recurse over file
    if (block->data_pos != 0) {
        inode_walker(st, block->data_pos, level, abspath, _callback);
    }

    // iterate over all subdirs
    if (block->next != 0)
        inode_walker(st, block->next, level, tabspath, _callback);

    unset_block(block);
}


/**
 * Walker callback's functions
 */

void display_tree(Block block, string &path, iNode st) {

    int level = block->level;

    //cout << path << endl;

    for (; level > 0; level--)
        printf("%c  ", 179);

    printf("%c%c%c%s\n", 195, 196, 196, block->name);

}

void path_builder(Block block, string &path, iNode st) {

#if _DEBUG_
    clock_t begin = clock();
    cout << path << endl;
#endif // _DEBUG_

    string extract_path = GetCurrentDir() + "data/" + path;

    if (!block->isFile) {
        // paths are already made recursively by makePath
        if (!makePath(getParentDir(extract_path), true)) {
            handle_error((string("path_builder :: makepath") + getParentDir(extract_path)).c_str(), 0);
        }
        return;
    }

    // fix for only files lockbox
    if (block->level == 1) {
        if (!makePath(getParentDir(extract_path), true)) {
            handle_error((string("path_builder :: makepath") + getParentDir(extract_path)).c_str(), 0);
        }
    }

    int fd = open(extract_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0x0666);

    if (fd < 0) {
        inode_debug_blockInfo(block, st->lockbox);
        return;
    }

    char *dst = (char *) mmap(nullptr, block->size, PROT_WRITE, MAP_FILE, fd, 0);

    if (dst == MAP_FAILED)
        return;

#if _DEBUG_
    cout << "after mmap" << " Time: " << double(clock() - begin) / CLOCKS_PER_SEC << "s" << endl;
    begin = clock();
#endif // _DEBUG_

    inode_read(st->lockbox, block->data_pos, dst, block->size);

    decript(dst, st->cipher, block->size);

#if _DEBUG_
    cout << "after write" << " Time: " << double(clock() - begin) / CLOCKS_PER_SEC << "s" << endl;
    begin = clock();
#endif // _DEBUG_

    msync(dst, block->size, MS_SYNC);

    munmap(dst, block->size);

    close(fd);

#if _DEBUG_
    cout << "after close" << " Time: " << double(clock() - begin) / CLOCKS_PER_SEC << "s" << endl;
    cout << endl;
#endif // _DEBUG_
}

/**
 * External functions
 */

void inode_build(iNode st, string inode_path) {

    pair<u_int, Block> p = inode_descending(st, inode_path, false);

    if (p.second != nullptr) {
        inode_walker(st, p.second->current, p.second->level, "", &path_builder);
    }

    unset_block(p.second);
}

void inode_display(iNode st) {
    cout << "==================================================================================================";
    cout << endl << "." << endl;

    inode_walker(st, st->root, 0, "", &display_tree);
}

iNode inode_load(string &path, char *cipher) {

    fix_path_escape(path);

    auto st = (iNode) malloc(sizeof(struct inode_st));
    auto tmp = (iNode) malloc(sizeof(struct inode_st));

    st->lockbox = open(path.c_str(), O_RDONLY);

    if (st->lockbox <= 0)
        handle_error("open::", 1);

    if (file_extenson(path) != "sc")
        return nullptr;

    inode_read(st->lockbox, 0, reinterpret_cast<void *>(tmp), sizeof(struct inode_st));

    st->root = tmp->root;

    memcpy(st->cipher, tmp->cipher, CRYPTO_HASH_DIM);

    decript(st->cipher, cipher, CRYPTO_HASH_DIM);

    st->cipher_check = tmp->cipher_check;

    free(tmp);

    if (hash_check(st->cipher) != hash_check(cipher)) {
        free(st);
        handle_error("Wrong password!", 1);
        return nullptr;
    }

    return st;
}

iNode inode_init(string &path, char *cipher) {

    fix_path_escape(path);

    auto st = (iNode) malloc(sizeof(struct inode_st));

    memcpy(st->cipher, cipher, CRYPTO_HASH_DIM);

    st->cipher_check = hash_check(cipher);

    if (access((basename(path) + "/lockbox.sc").c_str(), F_OK) != -1) {

        //if( remove( (basename(path) + "/lockbox.sc").c_str() ) == -1 )
        handle_error("lockbox.sc already exist", -1);
    }

    st->root = -1;
    st->lockbox = open((basename(path) + "/lockbox.sc").c_str(), O_RDWR | O_CREAT, 0x0777);

    if (st->lockbox == -1)
        handle_error("Opening output file: ", 255);

    // occupy iNode space
    inode_insert(st->lockbox, st, sizeof(struct inode_st));

    string base;

    if (is_file(path.c_str())) {
        base = basename(path);
    } else {
        base = path;
    }

    auto root = initialize_block();

    strcpy(root->name, "root");

    st->root = root->current = inode_insert_block(st->lockbox, root);

    inode_update_block(st->lockbox, root);

    unset_block(root);

    path_walker(st, path, filename(path));

    return st;
}

void inode_close(iNode st) {
    char cipher[CRYPTO_HASH_DIM];

    memcpy(cipher, st->cipher, CRYPTO_HASH_DIM);

    encript(st->cipher, cipher, CRYPTO_HASH_DIM);

    // update iNode struct
    inode_write(st->lockbox, st, 0, sizeof(struct inode_st));
}
