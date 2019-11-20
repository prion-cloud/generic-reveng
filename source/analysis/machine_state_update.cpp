#include <generic-reveng/analysis/machine_state_update.hpp>

namespace grev
{
    void machine_state_update::set(z3_expression key, std::vector<z3_expression> operands,
        std::function<z3_expression (std::vector<z3_expression>)> operation)
    {
        parts_.push_back(
            part
            {
                .key = std::move(key),
                .operands = std::move(operands),
                .operation = std::move(operation)
            });
    }
    void machine_state_update::set_jump(z3_expression value)
    {
        parts_.push_back(
            part
            {
                .key = std::nullopt,
                .operands = { std::move(value) },
                .operation = [](auto operands) { return std::move(operands[0]); }
            });
    }

    std::unordered_set<z3_expression> machine_state_update::resolve(machine_state* const state) const
    {
        std::unordered_set<z3_expression> jumps;

        for (auto part : parts_)
        {
            for (auto& operand : part.operands)
                operand = (*state)[operand];

            auto value = part.operation(std::move(part.operands));

            if (part.key)
                state->revise(std::move(*part.key), std::move(value));
            else
                jumps.insert(std::move(value));
        }

        return jumps;
    }
}
