#include "stdafx.h"

#include "disassembly.h"
#include "serialization.h"

disassembly_x86::disassembly_x86(const std::vector<instruction_x86> instructions)
    : instructions_(instructions) { }

void disassembly_x86::save(const std::string file_name) const
{
    FATAL_IF(serialize(file_name, instructions_));
}

std::set<uint64_t> disassembly_x86::find_sequences(const int min, const unsigned find, const std::set<unsigned> add) const
{
    std::set<uint64_t> result;

    for (auto i = 0; i < instructions_.size(); ++i)
    {
        const auto ins = instructions_.at(i);

        if (ins.get_id() != find)
            continue;

        auto j = 0;

        do
        {
            ++i;
            ++j;

            if (i >= instructions_.size())
                break;
        }
        while (instructions_.at(i).get_id() == find || add.find(instructions_.at(i).get_id()) != add.end());

        if (j >= min)
            result.insert(ins.get_address());
    }

    return result;
}
std::map<uint64_t, std::vector<uint64_t>> disassembly_x86::find_immediates(const std::set<uint64_t> imm, const std::set<unsigned> consider) const
{
    std::map<uint64_t, std::vector<uint64_t>> result;

    for (const auto ins : instructions_)
    {
        if (consider.find(ins.get_id()) == consider.end())
            continue;

        for (const auto op : ins.get_operands())
        {
            if (op.first != X86_OP_IMM || imm.find(op.second) == imm.end())
                continue;

            result[op.second].push_back(ins.get_address());
            break;
        }
    }

    return result;
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
    std::vector<instruction_x86> instructions;
    FATAL_IF(deserialize(file_name, instructions));

    return disassembly_x86(instructions);
}
