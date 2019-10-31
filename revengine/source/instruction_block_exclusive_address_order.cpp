#include <revengine/instruction_block.hpp>

namespace rev
{
    bool instruction_block::exclusive_address_order::operator()(
        instruction_block const& instruction_block_1,
        instruction_block const& instruction_block_2) const
    {
        return instruction_block_1.rbegin()->address() < instruction_block_2.address();
    }

    bool instruction_block::exclusive_address_order::operator()(
        instruction_block const& instruction_block,
        std::uint64_t const address) const
    {
        return instruction_block.rbegin()->address() < address;
    }
    bool instruction_block::exclusive_address_order::operator()(
        std::uint64_t const address,
        instruction_block const& instruction_block) const
    {
        return address < instruction_block.address();
    }

    static_assert(std::is_destructible_v<instruction_block::exclusive_address_order>);

    static_assert(std::is_move_constructible_v<instruction_block::exclusive_address_order>);
    static_assert(std::is_move_assignable_v<instruction_block::exclusive_address_order>);

    static_assert(std::is_copy_constructible_v<instruction_block::exclusive_address_order>);
    static_assert(std::is_copy_assignable_v<instruction_block::exclusive_address_order>);
}
