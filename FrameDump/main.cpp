#include "stdafx.h"

#include "../Bin-Capstone/capstone.h"

static std::vector<cs_insn> disassemble_all(const uint64_t address, const std::vector<uint8_t> bytes)
{
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn* insn;
    const auto count = cs_disasm(handle, &bytes.at(0), bytes.size(), address, 0, &insn);

    cs_close(&handle);

    return std::vector<cs_insn>(insn, insn + count);
}

static std::map<uint64_t, size_t> find_sequences(std::vector<cs_insn> instructions, const int min, const unsigned find, const std::set<unsigned> add)
{
    std::map<uint64_t, size_t> sequences;

    for (auto i = 0; i < instructions.size(); ++i)
    {
        const auto ins = instructions.at(i);

        if (ins.id != find)
            continue;

        auto j = 0;

        do
        {
            ++i;
            ++j;

            if (i >= instructions.size())
                break;
        }
        while (instructions.at(i).id == find || add.find(instructions.at(i).id) != add.end());

        if (j >= min)
        {
            std::cout << "  " << std::hex << std::showbase << ins.address << " (" << j << ")" << std::endl;
            sequences.emplace(ins.address, j);
        }
    }

    return sequences;
}

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
        std::cerr << "Failed to open file." << std::endl;
        return -1;
    }

    file_stream.seekg(0, std::ios::end);
    std::vector<uint8_t> bytes(file_stream.tellg());
    file_stream.seekg(0, std::ios::beg);

    file_stream.read(reinterpret_cast<char*>(&bytes.at(0)), bytes.size());

    std::cout << "Size: " << bytes.size() << " bytes" << std::endl;

    // -----

    const uint64_t addr1 = 0x1000;
    const uint64_t addr2 = 0x989000;

    const std::vector<uint8_t> b_text1(bytes.begin() + addr1, bytes.begin() + 0x4b5a00);
    const std::vector<uint8_t> b_text2(bytes.begin() + addr2, bytes.begin() + 0xe66000);

/*
    std::vector<uint8_t> text;
    text.insert(text.end(), b_text1.begin(), b_text1.end());
    text.insert(text.end(), b_text2.begin(), b_text2.end());
*/

    const auto ins1 = disassemble_all(addr1, b_text1);
    const auto ins2 = disassemble_all(addr2, b_text2);

    const auto seq = find_sequences(ins2, 10, X86_INS_POP, { X86_INS_PUSHFQ, X86_INS_MOVUPD, X86_INS_LEA });

    // -----

    std::cin.get();
    return 0;
}
