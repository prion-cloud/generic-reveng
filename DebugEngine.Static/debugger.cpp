#include "stdafx.h"

#include "debugger.h"

debugger::debugger(loader& loader, const std::vector<uint8_t>& code)
    : loader_(loader)
{
    const auto machine = loader_.load(code);

    disassembler_ = std::make_unique<disassembler>(machine);
    emulator_ = loader_.get_emulator();

    next_instruction_ = disassemble_at(emulator_->address());
}

instruction_x86 debugger::next_instruction() const
{
    return next_instruction_;
}

traceback_x86 debugger::run(const size_t count)
{
    traceback_x86 traceback;

    size_t i = 0;

    bool cont;
    do
    {
        traceback = step_into();

        cont = true;

        const auto address = next_instruction_.address;
        if (debug_points_.find(address) != debug_points_.end())
        {
            const auto dp = debug_points_.at(address);

            switch(dp)
            {
            case dp_break:
                cont = false;
                break;
            case dp_skip:
                skip();
                break;
            case dp_take:
                take();
                break;
            }
        }

        if (count > 0 && ++i >= count)
            break;
    }
    while (cont);

    return traceback;
}

traceback_x86 debugger::step_into()
{
    /*
    if (byte_trace_pointer_.find(address) == byte_trace_pointer_.end())
    {
        byte_trace_pointer_.emplace(address, byte_trace_.size());
        byte_trace_.push_back(next_instruction_.code);
    }
    // else THROW("This may be a great case for an unordered map."); TODO

    if (global_flags.hot)
        ++counter_[address];
    */
/* TODO
    for (const auto reg : next_instruction_->registers)
        trace_entry.old_registers.emplace(reg.first, emulator_->reg_read<uint64_t>(reg.first));
*/

    traceback_x86 traceback(next_instruction_, static_cast<uc_err>(emulator_->emulate_once()),
        [this](const x86_reg reg)
        {
            if (reg == X86_REG_INVALID)
                return uint64_t { 0xBAD };
            return emulator_->reg_read<uint64_t>(reg);
        },
        [this](const uint64_t address)
        {
            if (!emulator_->mem_is_mapped(address))
                return uint64_t { 0xBAD };
            return emulator_->mem_read<uint64_t>(address);
        });

    /*
    switch (live.error)
    {
    case UC_ERR_READ_UNMAPPED:
    case UC_ERR_WRITE_UNMAPPED:
    case UC_ERR_FETCH_UNMAPPED:
        if (loader_.ensure_availability(emulator_->address()))
        {
            emulator_->jump_to(next_instruction_.address);
            return step_into(); // TODO: Prevent stack overflow
        }
    default:;
    }
    */

/* TODO
    for (const auto reg : next_instruction_->registers)
        trace_entry.new_registers.emplace(reg.second, emulator_->reg_read<uint64_t>(reg.first));
*/

    if (traceback.has_failed() && global_flags.ugly)
        skip();
    else next_instruction_ = disassemble_at(emulator_->address());

    return traceback;
}

int debugger::step_back()
{
    // TODO
    return RES_FAILURE;
}

int debugger::set_debug_point(const uint64_t address, const debug_point point)
{
    ERROR_IF(!emulator_->mem_is_mapped(address));

    debug_points_.emplace(address, point);
    return RES_SUCCESS;
}
int debugger::remove_debug_point(const uint64_t address)
{
    ERROR_IF(!is_debug_point(address));

    debug_points_.erase(address);
    return RES_SUCCESS;
}

int debugger::jump_to(const uint64_t address)
{
    // ERROR_IF(!emulator_->mem_is_mapped(address)); TODO (does not work any more)

    emulator_->jump_to(address);
    next_instruction_ = disassemble_at(address);
    return RES_SUCCESS;
}
int debugger::get_raw(const uint64_t address, uint64_t& raw_address, size_t& section_index, std::string& section_name) const
{
    raw_address = loader_.to_raw_address(address, section_index, section_name);

    ERROR_IF(raw_address == UINT64_MAX);
    return RES_SUCCESS;
}

int debugger::skip()
{
    return jump_to(next_instruction_.address + next_instruction_.code.size());
}
int debugger::take()
{   
/* TODO
    const auto jump = next_instruction_->jump;
    ERROR_IF(!jump.has_value());  
*/
    ERROR_IF(next_instruction_.type != ins_jump);
    return jump_to(std::get<op_immediate>(next_instruction_.operands.at(0).value));
}

bool debugger::is_debug_point(const uint64_t address) const
{
    return debug_points_.find(address) != debug_points_.end();
}

int debugger::get_bytes(const uint64_t address, const size_t count, std::vector<uint8_t>& bytes)
{
    ERROR_IF(byte_trace_pointer_.find(address) == byte_trace_pointer_.end());

    const auto start_vec_it = byte_trace_.begin() + byte_trace_pointer_.at(address);

    for (unsigned i = 0; i < count; ++i)
    {
        const auto cur_vec_it = start_vec_it + i;
        bytes.insert(bytes.end(), cur_vec_it->begin(), cur_vec_it->end());
    }

    return RES_SUCCESS;
}

// --- TODO Q&D
emulation_snapshot debugger::take_snapshot() const
{
    return emulator_->take_snapshot();
}
void debugger::reset(const emulation_snapshot& snapshot) const
{
    emulator_->reset(snapshot);
}

uint64_t debugger::image_base() const
{
    return loader_.image_base();
}
std::vector<code_section> debugger::sections() const
{
    return loader_.sections();
}
// ---

instruction_x86 debugger::disassemble_at(const uint64_t address) const
{
    const auto max_bytes = 16;

    std::vector<uint8_t> code(max_bytes);
    emulator_->mem_read(address, code);

    return disassembler_->disassemble(address, code);
    //ins.label = loader_.label_at(address);
}
