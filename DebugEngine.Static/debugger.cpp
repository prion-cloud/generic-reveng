#include "stdafx.h"

#include "debugger.h"

debugger::debugger(loader& loader, const std::vector<uint8_t> code)
    : loader_(loader)
{
    const auto machine = loader_.load(code);

    disassembler_ = std::make_unique<disassembler>(machine);
    emulator_ = loader_.get_emulator();

    next_instruction_ = disassemble_at(emulator_->address());
}

std::shared_ptr<instruction> debugger::next_instruction() const
{
    return next_instruction_;
}

debug_trace_entry debugger::step_into()
{
    debug_trace_entry trace_entry;

    const auto instruction = next_instruction_;

    for (const auto reg : instruction->registers)
        trace_entry.old_registers.emplace(reg.first, emulator_->reg_read<uint64_t>(reg.first));

    trace_entry.error = emulator_->step_into();
    trace_entry.error_str = uc_strerror(static_cast<uc_err>(trace_entry.error));

    switch (trace_entry.error)
    {
    case UC_ERR_READ_UNMAPPED:
    case UC_ERR_WRITE_UNMAPPED:
    case UC_ERR_FETCH_UNMAPPED:
        if (loader_.ensure_availablility(emulator_->address()))
        {
            emulator_->jump_to(instruction->address);
            return step_into(); // TODO: Prevent stack overflow
        }
    default:;
    }

    for (const auto reg : instruction->registers)
        trace_entry.new_registers.emplace(reg.second, emulator_->reg_read<uint64_t>(reg.first));

    if (trace_entry.error && global_flag_status.ugly)
        skip();
    else next_instruction_ = disassemble_at(emulator_->address());

    trace_.push_back(trace_entry);
    if (trace_.size() > MAX_TRACE)
        trace_.pop_front();

    return trace_entry;
}

int debugger::step_back()
{
    ERROR_IF(trace_.size() < 2);

    const auto cur = trace_.at(trace_.size() - 1);
    const auto prev = trace_.at(trace_.size() - 2);

    trace_.pop_back();

    for (const auto old_reg : cur.old_registers)
        emulator_->reg_write(old_reg.first, old_reg.second);

    ERROR_IF(jump_to(prev.address));

    return RES_SUCCESS;
}
int debugger::set_breakpoint(const uint64_t address)
{
    ERROR_IF(emulator_->mem_is_mapped(address));

    breakpoints_.insert(address);
    return RES_SUCCESS;
}
int debugger::jump_to(const uint64_t address)
{
    ERROR_IF(emulator_->mem_is_mapped(address));

    emulator_->jump_to(address);
    next_instruction_ = disassemble_at(address);
    return RES_SUCCESS;
}
int debugger::skip()
{
    return jump_to(next_instruction_->address + next_instruction_->bytes.size());
}

std::shared_ptr<instruction> debugger::disassemble_at(const uint64_t address) const
{
    std::vector<uint8_t> bytes(MAX_BYTES);
    emulator_->mem_read(address, bytes);

    const auto instruction = disassembler_->disassemble(bytes, address);
    instruction->label = loader_.label_at(address);

    return instruction;
}
