#pragma once

#include <unordered_map>

#include <decompilation/expression.hpp>

namespace dec
{
    class expression_block : std::unordered_map<expression, expression>
    {
    public:

        expression const& operator[](expression const& key) const;

        expression& operator[](expression const& key);
        expression& operator[](std::string const& name);
    };
}
