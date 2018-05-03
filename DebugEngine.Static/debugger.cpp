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

int debugger::step_into(instruction& instruction, std::string& label, std::map<std::string, uint64_t>& registers) const
{
    const auto address = emulator_->address();

    uint8_t bytes[MAX_BYTES];
    emulator_->mem_read(address, bytes, MAX_BYTES);

    disassembler_->disassemble(bytes, address, instruction);

    const auto res = emulator_->step_into();

    if (res == UC_ERR_FETCH_UNMAPPED && loader_->validate_availablility(emulator_->address()))
    {
        emulator_->jump(address);
        return step_into(instruction, label, registers);
    }

    for (const auto reg : instruction.registers)
        registers.emplace(reg.second, emulator_->reg_read<uint64_t>(reg.first));

    const auto labels = loader_->get_labels();
    label = labels.find(address) != labels.end()
        ? labels.at(address)
        : std::string();

    if (res && global_flag_status.ugly)
        emulator_->jump(address + instruction.bytes.size());

    return res;
}
