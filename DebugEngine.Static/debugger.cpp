#include "stdafx.h"

#include "debugger.h"

debugger::debugger(loader* loader, const std::vector<uint8_t> byte_vec)
{
    loader_ = loader;

    const auto machine = loader_->load(byte_vec);
    E_FAT(machine == 0x0);

    disassembler_ = new disassembler(machine);
    emulator_ = loader_->get_emulator();
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
    disassembler_->disassemble(bytes, address, instruction, regs);

    const auto res = emulator_->step_into();

    if (res == 8 && loader_->validate_availablility(emulator_->address()))
    {
        emulator_->jump(address);
        return debug(instruction, label, registers);
    }

    for (const auto reg : regs)
        registers.emplace(reg.second, emulator_->reg_read<uint64_t>(reg.first));

    const auto labels = loader_->get_labels();
    label = labels.find(address) != labels.end()
        ? labels.at(address)
        : std::string();

    return res;
}
