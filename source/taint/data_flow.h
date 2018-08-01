#pragma once

#include <functional>
#include <optional>
#include <variant>
#include <vector>

#include "data_value.h"

#include "../instruction.h"

namespace taint
{
    struct data_flow_contextual
    {
        data_value destination;
        std::vector<data_value> sources;

        std::function<data_value(std::vector<data_value*> const&)> operation;
    };

    class data_flow_abstracted
    {
        enum class operation { add, sub, mul, div };

        class operand
        {
            enum class modifier { neg, inv, ref, ind };

            std::variant<unsigned, instruction::operand> value_;
            std::optional<modifier> modifier_;

        public:

            data_value evaluate(std::vector<instruction::operand> const& operands) const;
        };

        operand destination_;
        std::vector<operand> sources_;

        std::optional<operation> operation_;

    public:

        data_flow_abstracted() = default;

        data_flow_contextual make_contextual(std::vector<instruction::operand> const& context) const;
    };
}
