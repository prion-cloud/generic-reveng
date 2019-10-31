#include <revengine/instruction.hpp>

namespace rev
{
    std::uint64_t instruction::address() const
    {
        return address_;
    }
    std::size_t instruction::size() const
    {
        return size_;
    }

    machine_impact const& instruction::impact() const
    {
        return impact_;
    }

    static_assert(std::is_destructible_v<instruction>);

    static_assert(std::is_move_constructible_v<instruction>);
    static_assert(std::is_move_assignable_v<instruction>);

    static_assert(std::is_copy_constructible_v<instruction>);
    static_assert(std::is_copy_assignable_v<instruction>);
}
