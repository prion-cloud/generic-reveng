#include <generic-reveng/analysis/machine_state.hpp>

namespace grev
{
    void machine_state::revise(z3_expression const& key, z3_expression value)
    {
        insert_or_assign(key, std::move(value));
    }
    void machine_state::reset()
    {
        clear();
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
static_assert(std::is_nothrow_move_constructible_v<grev::machine_state>);

static_assert(std::is_copy_assignable_v<grev::machine_state>);
static_assert(std::is_nothrow_move_assignable_v<grev::machine_state>);
