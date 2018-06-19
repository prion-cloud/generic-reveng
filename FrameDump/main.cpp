#include "stdafx.h"

#include "../Bin-Capstone/capstone.h"

#include "deobfuscator.h"
#include "disassembly.h"

#define FILE_1 "text1.dis"
#define FILE_2 "text2.dis"

/*
static void process(const std::vector<uint8_t> bytes, const uint64_t virtual_base, const uint64_t raw_address, const size_t length, const std::string out_file_name)
{
    const auto start = bytes.begin() + raw_address;
    const std::vector<uint8_t> section(start, start + length);

    disassembly_part_x86::create_complete(virtual_base, raw_address, section).save(out_file_name);
}

static void make(const std::vector<uint8_t> bytes)
{
    auto a = sizeof(instruction_x86);

    process(bytes, 0x7ff7e42d0000, 0x1000, 0x4b4a00, FILE_1);
    process(bytes, 0x7ff7e42d0000, 0x989000, 0x4dd000, FILE_2);

    std::cout << "Complete" << std::endl;

    disassembly_part_x86 load;
    load.load(FILE_2);
    const auto seq = load.crawl_sequences(10, X86_INS_PUSH, { X86_INS_PUSHFQ, X86_INS_MOVUPD, X86_INS_LEA });
}
*/

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

    /*
    disassembly_x86 disassembly;
    disassembly.load_part(FILE_1);
    disassembly.load_part(FILE_2);
    */

    /*
    obfuscation_x86 obfuscation(&disassembly, 0x40B955);// = obfuscation_framed_x86::pick_all(&disassembly).at(3);

    obfuscation.emerge_calls();
    */

    //const auto graph = obfuscation_graph_x86::build(&disassembly, 0x7FF7E4C59000, 0x7FF7E46A7B2B);

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
