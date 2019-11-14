#pragma once

#include <generic-reveng/analysis/z3/expression.hpp>

namespace grev
{
    class machine_impact :
        std::unordered_map<expression, expression>
    {
    public:

        void revise(expression const& key, expression const& value);

        expression const& operator[](expression const& key) const;
    };
}
