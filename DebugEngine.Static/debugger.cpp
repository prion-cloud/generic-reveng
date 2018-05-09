#include "stdafx.h"

#include "debugger.h"

debugger::debugger(loader& loader, const std::vector<uint8_t> byte_vec)
    : loader_(loader)
{
    const auto machine = loader_.load(byte_vec);
    E_FAT(machine == 0x0);

    disassembler_ = new disassembler(machine);
    emulator_ = loader_.get_emulator();
}
debugger::~debugger()
{
    delete disassembler_;
    delete emulator_;
}

debug_trace_entry debugger::step_into() const
{
    debug_trace_entry trace_entry;

    const auto address = emulator_->address();

    uint8_t bytes[MAX_BYTES];
    emulator_->mem_read(address, bytes, MAX_BYTES);

    disassembler_->disassemble(bytes, address, trace_entry.instruction);

    switch (trace_entry.error = emulator_->step_into())
    {
    case UC_ERR_READ_UNMAPPED:
    case UC_ERR_WRITE_UNMAPPED:
    case UC_ERR_FETCH_UNMAPPED:
        if (loader_.ensure_availablility(emulator_->address()))
        {
            emulator_->jump(address);
            return step_into(); // TODO: Prevent stack overflow
        }
    default:;
    }

    for (const auto reg : trace_entry.instruction.registers)
        trace_entry.registers.emplace(reg.second, emulator_->reg_read<uint64_t>(reg.first));

    const auto labels = loader_.get_labels();
    trace_entry.label = labels.find(address) != labels.end()
        ? labels.at(address)
        : std::string();

    if (trace_entry.error && global_flag_status.ugly)
        emulator_->jump(address + trace_entry.instruction.bytes.size());

    return trace_entry;
}
