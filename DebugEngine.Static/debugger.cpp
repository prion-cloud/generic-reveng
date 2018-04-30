#include "stdafx.h"

#include "debugger.h"

debugger::debugger(loader* loader, const uint16_t machine, const std::vector<uint8_t> byte_vec)
{
    disassembler_ = new disassembler(machine);
    emulator_ = new emulator(machine);

    E_FAT(loader->load(emulator_, byte_vec));

    labels_ = loader->labels();
    deferrals_ = loader->deferrals();
}
debugger::~debugger()
{
    delete disassembler_;
    delete emulator_;
}

int debugger::debug(instruction& instruction, std::string& label, std::map<std::string, uint64_t>& registers) const
{
    const auto address = emulator_->address();

    if (deferrals_.find(address) != deferrals_.end())
    {
        const auto dll_name = deferrals_.at(address);

        // TODO
    }

    uint8_t bytes[MAX_BYTES];
    emulator_->mem_read(address, bytes, MAX_BYTES);

    std::map<x86_reg, std::string> regs;
    const auto next = disassembler_->disassemble(bytes, address, instruction, regs);

    const auto res = emulator_->step_into();

    for (const auto reg : regs)
        registers.emplace(reg.second, emulator_->reg_read<uint64_t>(reg.first));

    if (next != 0)
        emulator_->jump(next);

    if (labels_.find(address) != labels_.end())
        label = labels_.at(address);
    else label = { };

    return res;
}
