#ifndef INODE_H
#define INODE_H

#include <string>

using namespace std;

#define PATH_SIZE 512

typedef struct inode_st *iNode;

/**
 * inizializza un inode con un direttorio passato come parametro
 **/
iNode inode_init(string &path, char *cipher);

/**
 * legge un inode da file
 **/
iNode inode_load(string &path, char *cipher);

/**
 * visualiza un'inode a schermo
 **/
void inode_display(iNode st);

/**
 * recreate the Dir structure from inode
 **/
void inode_build(iNode st, string inode_path);

/**
 * save the current iNode
 */
void inode_close(iNode st);

#endif // INODE_H
