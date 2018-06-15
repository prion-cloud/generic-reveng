#include "stdafx.h"

#include "../Bin-Capstone/capstone.h"

#include "instruction.h"
#include "serialization.h"

#define FILE_1 "text1.dis"
#define FILE_2 "text2.dis"

static std::shared_ptr<std::vector<instruction_x86>> disassemble_all(const uint64_t address, const std::vector<uint8_t> bytes)
{
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn* c_disassembly;
    const auto count = cs_disasm(handle, &bytes.at(0), bytes.size(), address, 0, &c_disassembly);

    cs_close(&handle);

    auto disassembly = std::make_shared<std::vector<instruction_x86>>(c_disassembly, c_disassembly + count);

    cs_free(c_disassembly, count);

    return disassembly;
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
        std::cerr << "Could not open file." << std::endl;
        return -1;
    }

    std::vector<uint8_t> bytes(get_size(file_stream));
    file_stream.read(reinterpret_cast<char*>(&bytes.at(0)), bytes.size());

    std::cout << "Size: " << bytes.size() << " bytes" << std::endl;

    // -----

    const uint64_t addr1 = 0x1000;
    const uint64_t addr2 = 0x989000;

    const std::vector<uint8_t> b_text1(bytes.begin() + addr1, bytes.begin() + addr1 + 0x4b4a00);
    const std::vector<uint8_t> b_text2(bytes.begin() + addr2, bytes.begin() + addr2 + 0x4dd000);

    const auto ins1 = disassemble_all(addr1, b_text1);
    instruction_x86::save(FILE_1, ins1);

    const auto ins2 = disassemble_all(addr2, b_text2);
    instruction_x86::save(FILE_2, ins2);

    std::cout << "Complete" << std::endl;

    // -----

    std::cin.get();
    return 0;
}
