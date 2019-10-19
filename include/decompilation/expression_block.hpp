#pragma once

#include <unordered_map>
#include <vector>

#include <decompilation/expression.hpp>

namespace dec
{
    class expression_block : std::unordered_map<expression, expression>
    {
    public:

        std::vector<std::string> to_string() const; // Debugging/testing purposes (TODO)

        void update(expression_block other);

        expression& operator[](expression const& key);
        expression& operator[](std::string const& key_name);

        expression const& operator[](expression const& key) const;

        bool operator==(expression_block other) const;
        bool operator!=(expression_block const& other) const;
    };
}
