#include <conio.h>
#include <dirent.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define __MINGW_USE_STD_BYTE 0
#include <windows.h>
#endif

#include "utility.h"
#include "filesystem.h"



uint32_t countOccurrences(void **elements, size_t elemsNro, size_t memory_size) {

    size_t occ = 0;

    void **ptrJ;
    void **ptrI = elements;

    for (size_t i = 0; i < elemsNro; i++) {

        for (size_t j = i + 1; j < elemsNro; j++) {

            ptrJ = reinterpret_cast<void **>((char **) ptrI + j);

            if (memcmp(*ptrI, *ptrJ, memory_size) == 0) {
                occ++;
                printf("%s - %s\n", (char *) *ptrI, (char *) *ptrJ);
            }
        }

        ptrI = reinterpret_cast<void **>((char **) elements + i);
    }

    return occ;
}

char *get_password(unsigned int len) {
    len++;
    unsigned int i;
    // todo handle max password lenght
    char c, *password = (char *) malloc(sizeof(char) * 1024);

    i = 0;
    password[0] = '\0';
    while ((c = getch()) != '\r')  //Loop until 'Enter' is pressed
    {
        switch (c) {
            case 0: //Catches f1-f12
            {
                getch();
                break;
            }
            case (char) 0xE0: //Catches arrow keys, end, home, page up/down, etc.
            {
                getch();
                break;
            }
            case '\b': {
                if (strlen(password) > 0)  //If the password string contains data, erase last character
                {
                    printf("\b \b");
                    if (i < len - 1)
                        password[--i] = '\0';
                }
                break;
            }
            default: {
                password[i % (len - 1)] = c;
                if (i < (len - 1))
                    password[(++i) % len] = '\0';
                else
                    i++;
                printf("*");

                break;
            }
        };
    }

    return password;
}

void handle_error(const char *msg, int code) {

    char buffer[300];

    sprintf(buffer, "ERROR:: ");

    if (strlen(msg) < 256)
        sprintf(buffer + strlen(buffer), msg);

    sprintf(buffer + strlen(buffer), ".");

    printf("%s", buffer);

    exit(code);
}

void wait(int milliseconds) {
    if (milliseconds == 0) {
        fflush(stdin);
        fflush(stdout);
        printf("Press any string to continue..");
        getch();
    } else Sleep(milliseconds);
}
