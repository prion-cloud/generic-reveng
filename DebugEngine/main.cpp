#include "stdafx.h"

#include "Windows.h"

#include <string>

#include <iomanip>
#include <iostream>

#define CMD_HELP "help"
#define CMD_EXIT "exit"

#define CMD_STEP_INTO "stepinto"

bool read_command()
{
    std::cout << "# ";

    std::string cmd;
    std::cin >> cmd;

    char x = std::cin.eof();

    if (cmd == CMD_HELP)
    {
        std::left(std::cout);
        std::cout << std::setw(20) << CMD_HELP << "print help" << std::endl;
        std::cout << std::setw(20) << CMD_EXIT << "exit program" << std::endl;
        std::cout << std::setw(20) << CMD_STEP_INTO << "debug next instruction" << std::endl;
    }
    else if (cmd == CMD_EXIT)
        return true;
    else if (cmd == CMD_STEP_INTO)
    {
        std::string arg;
        std::cin >> arg;

        auto a = 0;
    }
    else
    {
        std::cout << "Command not recognized." << std::endl;
    }

    std::cin.clear();
    std::cin.ignore(INT64_MAX, '\n');

    return false;
}

int main(const int argc, char* argv[])
{
    CONSOLE_FONT_INFOEX cfi;
    cfi.cbSize = sizeof cfi;
    cfi.nFont = 0;
    cfi.dwFontSize.X = 0;
    cfi.dwFontSize.Y = 24;
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcscpy_s(cfi.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &cfi);
    
    if (argc < 2)
    {
        std::cout << "No file specified.";
        return -1;
    }
    if (argc > 2)
    {
        std::cout << "Too many arguments.";
        return -1;
    }
/*
    for (;;)
    {
        if (read_command())
            break;
    }
*/
    return 0;
}
