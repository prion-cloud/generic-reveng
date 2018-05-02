#include "stdafx.h"

#include "debugger.h"

debugger::debugger(loader* loader, const uint16_t machine, const std::vector<uint8_t> byte_vec)
{
    loader_ = loader;

    disassembler_ = new disassembler(machine);
    emulator_ = new emulator(machine);

    E_FAT(loader->load(emulator_, byte_vec));
}
debugger::~debugger()
{
    delete disassembler_;
    delete emulator_;
}

int debugger::debug(instruction& instruction, std::string& label, std::map<std::string, uint64_t>& registers) const
{
    const auto address = emulator_->address();

    uint8_t bytes[MAX_BYTES];
    emulator_->mem_read(address, bytes, MAX_BYTES);

    std::map<x86_reg, std::string> regs;
    const auto next = disassembler_->disassemble(bytes, address, instruction, regs);

    const auto res = emulator_->step_into();

    if (res == 8 && loader_->validate_availablility(emulator_->address()))
    {
        emulator_->jump(address);
        return debug(instruction, label, registers);
    }

    for (const auto reg : regs)
        registers.emplace(reg.second, emulator_->reg_read<uint64_t>(reg.first));

    if (next != 0)
        emulator_->jump(next);

    const auto labels = loader_->labels();
    label = labels.find(address) != labels.end()
        ? labels.at(address)
        : std::string();

    return res;
}
