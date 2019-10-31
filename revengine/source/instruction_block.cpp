#include <revengine/instruction_block.hpp>

namespace rev
{
    instruction_block::instruction_block() = default;

    std::uint64_t instruction_block::address() const
    {
        return begin()->address();
    }

    // TODO (?)
    machine_impact instruction_block::impact() const
    {
        machine_impact impact;
        for (auto const& instruction : *this)
            impact.update(instruction.impact());

        return impact;
    }

    instruction_block instruction_block::extract_head(std::uint64_t const new_address)
    {
        auto const new_begin = find(new_address);

        if (new_begin == end())
            throw std::invalid_argument("Invalid address");

        instruction_block head;
        while (begin() != new_begin)
            head.insert(head.begin(), extract(std::prev(new_begin)));

        if (head.empty())
            throw std::invalid_argument("Nothing to extract");

        return head;
    }

    static_assert(std::is_destructible_v<instruction_block>);

    static_assert(std::is_move_constructible_v<instruction_block>);
    static_assert(std::is_move_assignable_v<instruction_block>);

    static_assert(std::is_copy_constructible_v<instruction_block>);
    static_assert(std::is_copy_assignable_v<instruction_block>);
}
