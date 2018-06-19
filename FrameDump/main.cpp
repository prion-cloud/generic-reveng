#include "stdafx.h"

#include "../Bin-Capstone/capstone.h"

#include "deobfuscator.h"

#define FILE_1 "text1.dis"
#define FILE_2 "text2.dis"

int main(const int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Invalid number of arguments." << std::endl;
        return -1;
    }

    const std::string file_name(argv[1]);

    std::cout << "File: \"" << file_name << "\"" << std::endl;

    std::ifstream file_stream(file_name, std::ios::binary);

    if (!file_stream.is_open())
    {
        std::cerr << "Could not open file." << std::endl;
        return -1;
    }

    file_stream.seekg(0, std::ios::end);
    std::vector<uint8_t> code(file_stream.tellg());

    file_stream.seekg(0, std::ios::beg);

    file_stream.read(reinterpret_cast<char*>(&code.at(0)), code.size());

    std::cout << "Size: " << code.size() << " bytes" << std::endl;

    // -----

    global_flags.lazy = true;
    global_flags.ugly = true;

    loader_pe loader;

    const deobfuscator_x86 deobfuscator(loader, code);
    deobfuscator.build(0x7FF7E4C59000, 0x7FF7E46A7B2B);

    // -----

    std::cout << "Complete" << std::endl;

    std::cin.get();
    return 0;
}
