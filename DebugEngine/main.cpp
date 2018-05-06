#include "stdafx.h"

#include <conio.h>
#include <iomanip>
#include <iostream>

#include "../DebugEngine.Static/debugger.h"

#define COL_DEF FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE

#define COL_FAIL FOREGROUND_RED | FOREGROUND_INTENSITY

#define COL_CALL FOREGROUND_GREEN | FOREGROUND_BLUE
#define COL_JUMP FOREGROUND_RED | FOREGROUND_GREEN
#define COL_LABEL FOREGROUND_GREEN
#define COL_REG FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY

#define COUT(color, stream) \
    { \
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); \
        std::cout stream; \
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COL_DEF); \
    }

#define FLAG_HELP "help"

#define FLAG_NO_FAT "nofat"
#define FLAG_LAZY "lazy"
#define FLAG_UGLY "ugly"

void init_console()
{
    const auto h_console = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_FONT_INFOEX cfi;
    cfi.cbSize = sizeof cfi;
    cfi.nFont = 0;
    cfi.dwFontSize.X = 0;
    cfi.dwFontSize.Y = 24;
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcscpy_s(cfi.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(h_console, FALSE, &cfi);

    SetConsoleTextAttribute(h_console, COL_DEF);

    CONSOLE_CURSOR_INFO info;
    info.dwSize = 100;
    info.bVisible = FALSE;
    SetConsoleCursorInfo(h_console, &info);
}

int inspect_args(std::vector<std::string> args, std::string& file_name, flag_status& flag_status)
{
    auto got_file_name = false;
    auto got_flag = false;

    for (const auto arg : args)
    {
        if (arg[0] == '-' && arg[1] == '-')
        {
            std::string flag = &arg[2];
            std::transform(flag.begin(), flag.end(), flag.begin(), tolower);

            if (flag == FLAG_HELP)
            {
                std::cout << "This is kind of a reverse engineering tool, I guess." << std::endl << std::endl;
                
                std::left(std::cout);

                std::cout << "\t" << std::setw(20) << "--" FLAG_HELP << "Print this help." << std::endl << std::endl;
                
                std::cout << "\t" << std::setw(20) << "--" FLAG_NO_FAT << "Disable fatal errors." << std::endl;
                std::cout << "\t" << std::setw(20) << "--" FLAG_LAZY << "Do any memory allocation once it is needed." << std::endl;
                std::cout << "\t" << std::setw(20) << "--" FLAG_UGLY << "Ignore instruction failures." << std::endl;

                return 1;
            }
            
            if (flag == FLAG_NO_FAT)
                flag_status.fat = false;
            else if (flag == FLAG_LAZY)
                flag_status.lazy = true;
            else if (flag == FLAG_UGLY)
                flag_status.ugly = true;
            else return -1;

            std::cout << "Flag: " << flag << std::endl;
            got_flag = true;

            continue;
        }

        if (got_file_name)
            return -1;

        file_name = arg;
        got_file_name = true;
    }

    if (!got_file_name)
        return -1;

    if (!got_flag)
        std::cout << "No flags specified." << std::endl;

    std::cout << std::endl;

    return 0;
}

std::vector<uint8_t> dump_file(const std::string file_name)
{
    FILE* file;
    fopen_s(&file, file_name.c_str(), "rb");

    fseek(file, 0, SEEK_END);
    const auto length = ftell(file);
    rewind(file);

    const auto buffer = static_cast<char*>(malloc(length));
    fread(buffer, sizeof(char), length, file);
    fclose(file);

    const auto byte_vec = std::vector<uint8_t>(buffer, buffer + length);
    free(buffer);

    return byte_vec;
}

void show_debug(debugger* dbg, std::map<std::string, uint64_t>& registers)
{
    registers.clear();

    instruction instruction;
    std::string label;

    const auto err = dbg->step_into(instruction, label, registers);

    std::cout << std::hex << std::right <<
#ifdef _WIN64
        std::setw(16)
#else
        std::setw(8)
#endif
    << instruction.address;

    if (!registers.empty())
        COUT(COL_REG, << "*")
    else std::cout << " ";
    
    if (err)
        COUT(COL_FAIL, << "X")
    else std::cout << " ";

    std::cout << "\t";

    auto col = COL_DEF;
    if (instruction.id == 0x10a)
        col = COL_JUMP;
    if (instruction.id == 0x038 || instruction.id == 0x095)
        col = COL_CALL;
    COUT(col, << instruction.mnemonic << " " << instruction.operands)

    if (!label.empty())
    {
        std::cout << " ";
        COUT(COL_LABEL, << "<" << label << ">")
    }

    std::cout << std::endl;
}
void show_regs(std::map<std::string, uint64_t> registers)
{
    auto first = true;
    for (const auto reg : registers)
    {
        if (!first)
            std::cout << " ";

        auto reg_name = reg.first;
        std::transform(reg_name.begin(), reg_name.end(), reg_name.begin(), toupper);

        COUT(COL_REG, << reg_name << ": " << std::hex << reg.second)

        first = false;
    }

    registers.clear();

    std::cout << std::endl;
}

int main(const int argc, char* argv[])
{
    init_console();
    
    std::string file_name;
    const auto res = inspect_args(std::vector<std::string>(argv + 1, argv + argc), file_name, global_flag_status);
    if (res < 0)
    {
        std::cout << "Invalid arguments.";
        return -1;
    }
    if (res > 0)
    {
        std::cout << std::endl << "Press any key to exit...";
        _getch();
        return 0;
    }

    struct stat buf;
    if (stat(file_name.c_str(), &buf))
    {
        std::cout << "Specified file does not exist.";
        return -1;
    }

    std::cout << std::string(68, '=') << std::endl;
    std::cout << "Press...";
    std::left(std::cout);
    std::cout << " " << std::setw(10) << "SPACE" << "to debug the next instruction" << std::endl;
    std::cout << "\t " << std::setw(10) << "r" << "to display recently accessed registers (* if any)" << std::endl;
    std::cout << "\t " << std::setw(10) << "x" << "to quit" << std::endl;
    std::cout << std::string(68, '=') << std::endl;
    std::cout << std::endl;

    const auto loader = new loader_pe();

    if (!global_flag_status.lazy)
        std::cout << "Loading... ";

    const auto dbg = new debugger(loader, dump_file(file_name));

    std::cout << "File: \"" << file_name << "\"" << std::endl << std::endl;

    std::map<std::string, uint64_t> registers;

    auto regs_shown = false;

    for (;;)
    {
        const char c = _getch();

        if (c == ' ')
        {
            show_debug(dbg, registers);
            regs_shown = false;
        }

        if (c == 'r' && !registers.empty() && !regs_shown)
        {
            show_regs(registers);
            regs_shown = true;
        }

        if (c == 'x')
            break;
    }

    delete dbg;
    delete loader;
}
