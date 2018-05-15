#include "stdafx.h"

#include "debugger.h"

debugger::debugger(loader& loader, const std::vector<uint8_t> code)
    : loader_(loader)
{
    const auto machine = loader_.load(code);

    disassembler_ = new disassembler(machine);
    emulator_ = loader_.get_emulator();

    next_instruction_ = disassemble_at(emulator_->address());
}
debugger::~debugger()
{
    delete disassembler_;
    delete emulator_;
}

instruction debugger::disassemble_at(const uint64_t address) const
{
    uint8_t bytes[MAX_BYTES];
    emulator_->mem_read(address, bytes, MAX_BYTES);

    instruction instruction;
    disassembler_->disassemble(bytes, address, instruction);

    instruction.label = loader_.label_at(address);

    return instruction;
}

instruction debugger::next_instruction() const
{
    return next_instruction_;
}

debug_trace_entry debugger::step_into()
{
    debug_trace_entry trace_entry;

    const auto instruction = next_instruction_;

    trace_entry.error = emulator_->step_into();
    trace_entry.error_str = uc_strerror(static_cast<uc_err>(trace_entry.error));

    switch (trace_entry.error)
    {
    case UC_ERR_READ_UNMAPPED:
    case UC_ERR_WRITE_UNMAPPED:
    case UC_ERR_FETCH_UNMAPPED:
        if (loader_.ensure_availablility(emulator_->address()))
        {
            emulator_->jump_to(instruction.address);
            return step_into(); // TODO: Prevent stack overflow
        }
    default:;
    }

    for (const auto reg : instruction.registers)
        trace_entry.registers.emplace(reg.second, emulator_->reg_read<uint64_t>(reg.first));

    if (trace_entry.error && global_flag_status.ugly)
        skip();
    else next_instruction_ = disassemble_at(emulator_->address());

    return trace_entry;
}

void debugger::jump_to(const uint64_t address)
{
    emulator_->jump_to(address);
    next_instruction_ = disassemble_at(address);
}

void debugger::skip()
{
    jump_to(next_instruction_.address + next_instruction_.bytes.size());
}
