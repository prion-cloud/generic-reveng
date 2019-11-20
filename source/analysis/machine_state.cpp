#include <generic-reveng/analysis/machine_state.hpp>

namespace grev
{
    void machine_state::revise(z3_expression key, z3_expression value)
    {
        insert_or_assign(std::move(key), std::move(value));
    }

    z3_expression const& machine_state::operator[](z3_expression const& key) const
    {
        if (auto const entry = find(key); entry != end())
            return entry->second;

        return key;
    }
}

static_assert(std::is_destructible_v<grev::machine_state>);

static_assert(std::is_copy_constructible_v<grev::machine_state>);
static_assert(std::is_copy_assignable_v<grev::machine_state>);

static_assert(std::is_move_constructible_v<grev::machine_state>);
static_assert(std::is_move_assignable_v<grev::machine_state>);
