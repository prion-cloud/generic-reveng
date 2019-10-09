#include <decompilation/instruction_block.hpp>

namespace dec
{
    bool instruction_block::exclusive_address_order::operator()(
        instruction_block const& instruction_block_1,
        instruction_block const& instruction_block_2) const
    {
        return instruction_block_1.rbegin()->address < instruction_block_2.begin()->address;
    }

    bool instruction_block::exclusive_address_order::operator()(
        instruction_block const& instruction_block,
        std::uint64_t const address) const
    {
        return instruction_block.rbegin()->address < address;
    }
    bool instruction_block::exclusive_address_order::operator()(
        std::uint64_t const address,
        instruction_block const& instruction_block) const
    {
        return address < instruction_block.begin()->address;
    }

    static_assert(std::is_destructible_v<instruction_block::exclusive_address_order>);

    static_assert(std::is_move_constructible_v<instruction_block::exclusive_address_order>);
    static_assert(std::is_move_assignable_v<instruction_block::exclusive_address_order>);

    static_assert(std::is_copy_constructible_v<instruction_block::exclusive_address_order>);
    static_assert(std::is_copy_assignable_v<instruction_block::exclusive_address_order>);

    instruction_block::instruction_block() = default;

    instruction_block::instruction_block(disassembler const& disassembler, data_section data_section)
    {
        while (!data_section.data.empty())
        {
            auto const instruction = insert(end(), disassembler(data_section));

            data_section.address += instruction->size;
            data_section.data.remove_prefix(instruction->size);

            if (instruction->jump.size() != 1 ||
                !instruction->jump.begin()->has_value() ||
                instruction->jump.begin()->value() != data_section.address)
                break;
        }
    }

    instruction_block instruction_block::extract_head(iterator last)
    {
        instruction_block head;
        while (begin() != last)
            head.insert(head.begin(), extract(std::prev(last)));

        return head;
    }

    static_assert(std::is_destructible_v<instruction_block>);

    static_assert(std::is_move_constructible_v<instruction_block>);
    static_assert(std::is_move_assignable_v<instruction_block>);

    static_assert(std::is_copy_constructible_v<instruction_block>);
    static_assert(std::is_copy_assignable_v<instruction_block>);
}
