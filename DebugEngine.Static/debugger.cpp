#include "stdafx.h"

#include "debugger.h"

debugger::debugger(loader* loader, const uint16_t machine, const std::vector<uint8_t> byte_vec)
{
    disassembler_ = new disassembler(machine);
    emulator_ = new emulator(machine);

    E_FAT(loader->load(emulator_, byte_vec));

    sections_ = loader->sections();
    labels_ = loader->labels();
}
debugger::~debugger()
{
    delete disassembler_;
    delete emulator_;
}

int debugger::debug(instruction& instruction, std::string& label) const
{
    const auto address = emulator_->address();

    uint8_t bytes[MAX_BYTES];
    emulator_->mem_read(address, bytes, MAX_BYTES);

    const auto next = disassembler_->disassemble(bytes, address, instruction);

    emulator_->step_into();

    if (next != 0)
        emulator_->jump(next);

    if (labels_.find(address) != labels_.end())
        label = labels_.at(address);
    else label = { };

    return R_SUCCESS;
}
