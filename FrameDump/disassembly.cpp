#include "stdafx.h"

#include "disassembly.h"
#include "serialization.h"

disassembly_x86::disassembly_x86(const std::vector<instruction_x86> instructions)
    : instructions_(instructions) { }

void disassembly_x86::save(const std::string file_name) const
{
    std::ofstream(file_name, std::ios::binary)
        .write(reinterpret_cast<const char*>(&instructions_.at(0)), instructions_.size() * sizeof(instruction_x86));
}

disassembly_x86 disassembly_x86::create_complete(const uint64_t base_address, const std::vector<uint8_t> code)
{
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn* cs_instructions;
    const auto count = cs_disasm(handle, &code.at(0), code.size(), base_address, 0, &cs_instructions);

    cs_close(&handle);

    disassembly_x86 disassembly(std::vector<instruction_x86>(cs_instructions, cs_instructions + count));

    cs_free(cs_instructions, count);

    return disassembly;
}

disassembly_x86 disassembly_x86::load(const std::string file_name)
{
    std::ifstream file_stream(file_name, std::ios::binary);

    const auto size = get_size(file_stream);
    const auto count = size / sizeof(instruction_x86);

    const auto instructions = new instruction_x86[count];
    file_stream.read(reinterpret_cast<char*>(instructions), size);

    disassembly_x86 disassembly(std::vector<instruction_x86>(instructions, instructions + count));

    delete[] instructions;

    return disassembly;
}
