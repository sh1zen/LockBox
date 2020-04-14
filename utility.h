#ifndef UTILITY_H
#define UTILITY_H

#include <string>
#include <cstdint>

using namespace std;

uint32_t countOccurrences(void **elements, size_t elemsNro, size_t memory_size);

// lockbox
bool is_lockbox(string &path);

// general
void handle_error(const char *msg, int code);

// console layer
void wait(int);

void SetColor(unsigned short);

void SelectColor(unsigned short);

void clrscr(int);


// support
char *itoa(int, char *, int);

char *get_password(unsigned int len = 0);


#endif

#define TIME 1
