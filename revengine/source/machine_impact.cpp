#include <revengine/machine_impact.hpp>

namespace rev
{
    void machine_impact::revise(z3::expression const& key, z3::expression const& value)
    {
        insert_or_assign(key, value);
    }

    z3::expression const& machine_impact::operator[](z3::expression const& key) const
    {
        if (auto const entry = find(key); entry != end())
            return entry->second;

        return key;
    }
}

static_assert(std::is_destructible_v<rev::machine_impact>);

static_assert(std::is_copy_constructible_v<rev::machine_impact>);
static_assert(std::is_copy_assignable_v<rev::machine_impact>);

static_assert(std::is_move_constructible_v<rev::machine_impact>);
static_assert(std::is_move_assignable_v<rev::machine_impact>);
