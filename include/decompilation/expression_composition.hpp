#pragma once

#include <unordered_map>
#include <vector>

#include <decompilation/expression.hpp>

namespace dec
{
    class expression_composition : std::unordered_map<expression, expression>
    {
    public:

        void update(expression_composition expression_composition);

        expression& operator[](expression const& key);
        expression& operator[](std::string const& key_name);

        std::vector<std::string> str() const; // Debugging/testing purposes (TODO)

        expression const& operator[](expression const& key) const;

        bool operator==(expression_composition other) const;
        bool operator!=(expression_composition const& other) const;
    };
}
