#pragma once

#include <list>
#include <unordered_set>

#include <generic-reveng/analysis/machine_state.hpp>

namespace grev
{
    struct machine_state_update_part
    {
        std::optional<z3::expression> key;
        std::function<z3::expression (z3::expression)> key_operation;

        std::vector<z3::expression> operands;

        std::function<z3::expression (std::vector<z3::expression>)> value_operation;
    };

    class machine_state_update : std::list<machine_state_update_part>
    {

    public:

        void set(machine_state_update_part part);

        std::unordered_set<z3::expression> resolve(machine_state* state) const;
    };
}
