#pragma once

#include <optional>
#include <unordered_map>
#include <vector>

#include "instruction.h"
#include "value.h"

class translator
{
    class flow
    {
        enum class operation { add, sub, mul, div };

        class specificator
        {
            enum class modification { neg, inv, ref, ind };

            std::variant<unsigned, operand> value_;
            std::optional<modification> modification_;

        public:

            value evaluate(instruction const& instruction) const;
        };

        std::optional<operation> operation_;

        specificator destination_;
        std::vector<specificator> sources_;

    public:

        std::pair<value, value> evaluate(instruction const& instruction) const;

    private:

        value evaluate_sources(instruction const& instruction) const;
    };

    std::unordered_map<unsigned, std::vector<flow>> dictionary_;

public:

    translator() = default;

    void load(std::istream& stream);
    void store(std::ostream& stream) const;

    std::vector<std::pair<value, value>> operator[](instruction const& instruction) const;
};
