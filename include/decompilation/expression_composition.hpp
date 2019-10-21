#pragma once

#include <unordered_map>
#include <vector>

#include <decompilation/expression.hpp>

namespace dec
{
    class expression_composition : std::unordered_map<expression, expression>
    {
    public:

        std::vector<std::string> to_string() const; // Debugging/testing purposes (TODO)

        expression update(expression expression) const;
        expression_composition update(expression_composition const& expression_composition) const;

        expression& operator[](expression const& key);
        expression& operator[](std::string const& key_name);

        expression const& operator[](expression const& key) const;

        bool operator==(expression_composition other) const;
        bool operator!=(expression_composition const& other) const;
    };
}
