#include <generic-reveng/analysis/machine_impact.hpp>

namespace grev
{
    void machine_impact::revise(expression const& key, expression const& value)
    {
        insert_or_assign(key, value);
    }

    expression const& machine_impact::operator[](expression const& key) const
    {
        if (auto const entry = find(key); entry != end())
            return entry->second;

        return key;
    }
}

static_assert(std::is_destructible_v<grev::machine_impact>);

static_assert(std::is_copy_constructible_v<grev::machine_impact>);
static_assert(std::is_copy_assignable_v<grev::machine_impact>);

static_assert(std::is_move_constructible_v<grev::machine_impact>);
static_assert(std::is_move_assignable_v<grev::machine_impact>);
