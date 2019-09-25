#include <decompilation/instruction_impact.hpp>

std::size_t std::hash<z3::expr>::operator()(z3::expr const& expression) const
{
    return expression.hash();
}

namespace dec
{
    static_assert(std::is_destructible_v<instruction_impact>);

    static_assert(std::is_move_constructible_v<instruction_impact>);
    static_assert(std::is_move_assignable_v<instruction_impact>);

    static_assert(std::is_copy_constructible_v<instruction_impact>);
    static_assert(std::is_copy_assignable_v<instruction_impact>);
}
