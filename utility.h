#ifndef UTILITY_H
#define UTILITY_H

#include <windows.h>

#include <string>

using namespace std;

// lockbox
bool is_lockbox(string &path);

// general
void handle_error(const char *msg, int code);

// console interface
void wait(int);

void SetColor(unsigned short);

void SelectColor(unsigned short);

void clrscr(int);


// support
char *itoa(int, char *, int);

char *get_password(unsigned int len);


#endif

#define TIME 1
