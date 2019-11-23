#include <generic-reveng/analysis/machine_state_update.hpp>

namespace grev
{
    void machine_state_update::set(machine_state_update_part part)
    {
        push_back(std::move(part));
    }

    std::unordered_set<z3::expression> machine_state_update::resolve(machine_state* const state) const
    {
        std::unordered_set<z3::expression> jumps;

        for (auto const& part : *this)
        {
            std::vector<z3::expression> resolved_operands;
            resolved_operands.reserve(part.operands.size());

            for (auto const& operand : part.operands)
            {
                auto& resolved_operand = resolved_operands.emplace_back((*state)[operand]);

                while (true)
                {
                    auto const& resolved_resolved_operand = (*state)[resolved_operand];

                    static constexpr std::equal_to<z3::expression> equal;
                    if (equal(resolved_resolved_operand, resolved_operand))
                        break;

                    resolved_operand = resolved_resolved_operand;
                }
            }

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