#pragma once

#include <unordered_set>

#include <generic-reveng/analysis/machine_state.hpp>

namespace grev
{
    struct machine_state_update_part
    {
        std::optional<z3_expression> key;
        std::function<z3_expression (z3_expression)> key_operation;

        std::vector<z3_expression> operands;

        std::function<z3_expression (std::vector<z3_expression>)> value_operation;
    };

    class machine_state_update : std::vector<machine_state_update_part>
    {

    public:

        void set(machine_state_update_part part);

        std::unordered_set<z3_expression> resolve(machine_state* state) const;
    };
}
