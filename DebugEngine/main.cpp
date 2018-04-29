#include "stdafx.h"

#include <iomanip>
#include <iostream>

#include "../DebugEngine.Static/debugger.h"

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

    const auto file_name = argv[1];

    struct stat buf;
    if (stat(file_name, &buf))
    {
        std::cout << "Specified file does not exist.";
        return -1;
    }

    const auto loader = new loader_pe();

    auto dbg = debugger(loader, IMAGE_FILE_MACHINE_I386, dump_file(file_name));

    delete loader;

    std::cout << "File loaded: \"" << file_name << "\"" << std::endl;

    for (;;)
    {
        std::cin.get();

        instruction instruction;
        std::string label;

        if (dbg.debug(instruction, label))
        {
            std::cout << "Something seems wrong.";
            return -1;
        }

        std::cout << std::hex << std::setw(8) << instruction.address;
        std::cout << "\t" << instruction.mnemonic << " " << instruction.operands;

        if (!label.empty())
            std::cout << " <" << label << ">";
    }
}
