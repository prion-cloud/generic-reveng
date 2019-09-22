#include <decompilation/instruction_block.hpp>

std::invalid_argument empty_instruction_block()
{
    return std::invalid_argument("Empty instruction block");
}

namespace dec
{
    bool instruction_block::exclusive_address_order::operator()(
        instruction_block const& instruction_block_1,
        instruction_block const& instruction_block_2) const
    {
        if (instruction_block_1.empty() || instruction_block_2.empty())
            throw empty_instruction_block();

        return instruction_block_1.rbegin()->address < instruction_block_2.begin()->address;
    }

    bool instruction_block::exclusive_address_order::operator()(
        instruction_block const& instruction_block,
        std::uint_fast64_t const address) const
    {
        if (instruction_block.empty())
            throw empty_instruction_block();

        return instruction_block.rbegin()->address < address;
    }
    bool instruction_block::exclusive_address_order::operator()(
        std::uint_fast64_t const address,
        instruction_block const& instruction_block) const
    {
        if (instruction_block.empty())
            throw empty_instruction_block();

        return address < instruction_block.begin()->address;
    }

    static_assert(std::is_destructible_v<instruction_block>);

    static_assert(std::is_move_constructible_v<instruction_block>);
    static_assert(std::is_move_assignable_v<instruction_block>);

    static_assert(std::is_copy_constructible_v<instruction_block>);
    static_assert(std::is_copy_assignable_v<instruction_block>);
}
