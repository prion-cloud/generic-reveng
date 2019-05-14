#include <stdexcept>

#include "common_exception.hpp"
#include "execution_engine.hpp"

reil_arch_t to_reil(dec::instruction_set_architecture const architecture)
{
    switch (architecture)
    {
        case dec::instruction_set_architecture::x86_32:
        case dec::instruction_set_architecture::x86_64:
            return ARCH_X86;

        // TODO
    }

    throw unknown_architecture();
}

int store_recent_reil_instruction(reil_inst_t* const reil_instruction, void* const reil_instruction_vector)
{
    auto& _reil_instruction_vector = *static_cast<std::vector<reil_inst_t>*>(reil_instruction_vector);

    if (reil_instruction->inum == 0)
        _reil_instruction_vector.clear();

    _reil_instruction_vector.push_back(*reil_instruction);

    return 0;
}

namespace dec
{
    execution_engine::execution_engine(instruction_set_architecture const architecture) :
        reil_handle_(reil_init(to_reil(architecture), store_recent_reil_instruction, &recent_reil_instructions_)) { }
    execution_engine::~execution_engine()
    {
        reil_close(reil_handle_);
    }

    instruction execution_engine::disassemble(std::uint_fast64_t const address, std::basic_string_view<std::byte> const& code)
    {
        reil_translate_insn(
            reil_handle_,
            address,
            // NOLINTNEXTLINE [cppcoreguidelines-pro-type-reinterpret-cast]
            reinterpret_cast<std::uint_fast8_t*>(
                // NOLINTNEXTLINE [cppcoreguidelines-pro-type-const-cast]
                const_cast<std::byte*>(
                    code.data())),
            std::min(code.size(), static_cast<std::size_t>(MAX_INST_LEN)));

        return
        {
            .address = recent_reil_instructions_.front().raw_info.addr,
            .size = static_cast<std::size_t>(recent_reil_instructions_.front().raw_info.size),

            .jumps = recent_instruction_jumps()
        };
    }

    std::unordered_set<std::optional<std::uint_fast64_t>> execution_engine::recent_instruction_jumps()
    {
        std::unordered_set<std::optional<std::uint_fast64_t>> jumps;

        auto step = true;

        for (auto const& reil_instruction : recent_reil_instructions_)
        {
            switch (reil_instruction.op)
            {
                case I_UNK:
                {
                    step = false;
                    break;
                }
                case I_JCC:
                {
                    switch (reil_instruction.c.type)
                    {
                        case A_LOC:
                        {
                            jumps.insert(reil_instruction.c.val);
                            break;
                        }
                        default:
                        {
                            jumps.insert(std::nullopt); // TODO
                            break;
                        }
                    }

                    step = reil_instruction.a.type != A_CONST || reil_instruction.a.val == 0;
                    break;
                }
                default:
                    break;
            }

            if (!step)
                break;
        }

        if (step)
            jumps.insert(recent_reil_instructions_.front().raw_info.addr + recent_reil_instructions_.front().raw_info.size);

        return jumps;
    }

    static_assert(std::is_destructible_v<execution_engine>);

    static_assert(std::is_move_constructible_v<execution_engine>);
    static_assert(std::is_move_assignable_v<execution_engine>);

    static_assert(std::is_copy_constructible_v<execution_engine>);
    static_assert(std::is_copy_assignable_v<execution_engine>);
}
