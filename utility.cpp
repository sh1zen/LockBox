// The following line is necessary for the GetConsoleWindow() function to work!
// it basically says that you are running this program on Windows 2000 or higher
#define _WIN32_WINNT 0x0500

#include <conio.h>
#include <dirent.h>

#include "utility.h"
#include "io_helpers.h"

char *get_password(unsigned int len) {
    len++;
    unsigned int i;
    char c, *password = (char *) malloc(sizeof(char) * len);

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

bool is_lockbox(string &path)
{
    return is_file(path.c_str()) and file_extenson(path) == "sc";
}

/* The Itoa code is in the puiblic domain */
char *itoa(int value, char *str, int radix) {
    static char dig[] =
            "0123456789"
            "abcdefghijklmnopqrstuvwxyz";
    int n = 0, neg = 0;
    unsigned int v;
    char *p, *q;
    char c;
    if (radix == 10 && value < 0) {
        value = -value;
        neg = 1;
    }
    v = value;
    do {
        str[n++] = dig[v % radix];
        v /= radix;
    } while (v);
    if (neg)
        str[n++] = '-';
    str[n] = '\0';
    for (p = str, q = p + n / 2; p != q; ++p, --q)
        c = *p, *p = *q, *q = c;
    return str;
}


void handle_error(const char *msg, int code) {

    GetLastError();

    perror(msg);

    exit(code);

}

void wait(int milliseconds) {
    if (milliseconds == 0) {
        fflush(stdin);
        fflush(stdout);
        printf("Press any key to continue..");
        getch();
    } else Sleep(milliseconds);
}

void SetColor(unsigned short color) {
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hCon, color);
}

void clrscr(int color) {
    DWORD n;                         // Number of characters written
    DWORD size;                      // number of visible characters
    COORD coord = {0, 0};             // Top left screen position
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);    //Get a handle to the console
    GetConsoleScreenBufferInfo(h, &csbi);
    size = csbi.dwSize.X * csbi.dwSize.Y;    //Find the number of characters to overwrite
    if (color > 0)
        SetColor(color);
    FillConsoleOutputCharacter(h, TEXT (' '), size, coord, &n);    // Overwrite the screen buffer with whitespace
    GetConsoleScreenBufferInfo(h, &csbi);
    FillConsoleOutputAttribute(h, csbi.wAttributes, size, coord, &n);
    SetConsoleCursorPosition(h, coord);    //Reset the cursor to the top left position
}
