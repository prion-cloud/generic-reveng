#include <decompilation/instruction.hpp>

namespace dec
{
    bool instruction::address_order::operator()(instruction const& instruction_1, instruction const& instruction_2) const
    {
        return instruction_1.address < instruction_2.address;
    }

    bool instruction::address_order::operator()(instruction const& instruction, std::uint64_t const address) const
    {
        return instruction.address < address;
    }
    bool instruction::address_order::operator()(std::uint64_t const address, instruction const& instruction) const
    {
        return address < instruction.address;
    }

    static_assert(std::is_destructible_v<instruction>);

    static_assert(std::is_move_constructible_v<instruction>);
    static_assert(std::is_move_assignable_v<instruction>);

    static_assert(std::is_copy_constructible_v<instruction>);
    static_assert(std::is_copy_assignable_v<instruction>);
}
