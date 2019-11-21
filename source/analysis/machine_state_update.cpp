#include <generic-reveng/analysis/machine_state_update.hpp>

namespace grev
{
    void machine_state_update::set(machine_state_update_part part)
    {
        push_back(std::move(part));
    }

    std::unordered_set<z3_expression> machine_state_update::resolve(machine_state* const state) const
    {
        std::unordered_set<z3_expression> jumps;

        for (auto const& part : *this)
        {
            std::vector<z3_expression> resolved_operands;
            resolved_operands.reserve(part.operands.size());

            for (auto const& operand : part.operands)
                resolved_operands.push_back((*state)[operand]);

            auto value = part.value_operation(std::move(resolved_operands)); // TODO part.resolve_value(*state)

            if (part.key)
            {
                if (part.key_operation)
                    state->revise(part.key_operation((*state)[*part.key]) /*TODO part.resolve_key(*state)*/, std::move(value));
                else
                    state->revise(*part.key, std::move(value));
            }
            else
                jumps.insert(std::move(value));
        }

        return jumps;
    }
}
