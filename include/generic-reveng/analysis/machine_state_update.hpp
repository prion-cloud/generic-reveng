#pragma once

#include <unordered_set>

#include <generic-reveng/analysis/machine_state.hpp>

namespace grev
{
    class machine_state_update
    {
        struct part
        {
            std::optional<z3_expression> key;

            std::vector<z3_expression> operands;
            std::function<z3_expression (std::vector<z3_expression>)> operation;
        };

        std::vector<part> parts_;

    public:

        void set(z3_expression key, std::vector<z3_expression> operands,
            std::function<z3_expression (std::vector<z3_expression>)> operation);
        void set_jump(z3_expression value);

        std::unordered_set<z3_expression> resolve(machine_state* state) const;
    };
}
