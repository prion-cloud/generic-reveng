#include "debugger.hpp"

uint64_t debugger::position() const
{
    return emulator_.read_register(ip_register_);
}
bool debugger::position(uint64_t const address)
{
    emulator_.write_register(ip_register_, address);

    return is_mapped();
}

cs_insn debugger::current_instruction() const
{
    auto address = position();
    auto code = emulator_.read_memory(address, disassembler::max_instruction_size);

    return disassembler_(&code, &address);
}

bool debugger::is_mapped() const
{
    return is_mapped(position());
}
bool debugger::is_mapped(uint64_t const address) const
{
    return true; // TODO
}

bool debugger::skip()
{
    return skip(current_instruction().size);
}
bool debugger::skip(uint64_t const count)
{
    return position(position() + count);
}

bool debugger::step_into()
{
    emulator_(position());

    return true; // TODO
}

debugger::debugger(executable_specification const& specification)
    : disassembler_(specification.architecture), emulator_(specification.architecture)
{
    int sp_register;
    int bp_register;

    switch (specification.architecture)
    {
    case machine_architecture::x86_32:
        ip_register_ = UC_X86_REG_EIP;
        sp_register = UC_X86_REG_ESP;
        bp_register = UC_X86_REG_EBP;
        break;
    case machine_architecture::x86_64:
        ip_register_ = UC_X86_REG_RIP;
        sp_register = UC_X86_REG_RSP;
        bp_register = UC_X86_REG_RBP;
        break;
    default:
        throw std::runtime_error("Unsupported architecture");
    }

    for (auto const& [address, data] : specification.memory_regions)
    {
        if (data.empty())
            continue;

        emulator_.allocate_memory(address, data.size());
        emulator_.write_memory(address, data);
    }

    position(specification.entry_point);

    auto constexpr stack_bottom = UINT32_MAX;
    auto constexpr stack_size = 0x1000;
    emulator_.allocate_memory(stack_bottom - stack_size + 1, stack_size);

    emulator_.write_register(sp_register, stack_bottom);
    emulator_.write_register(bp_register, stack_bottom);
}
