#pragma once

#include <generic-reveng/analysis/z3/expression.hpp>

namespace grev
{
    class machine_state : std::unordered_map<z3::expression, z3::expression>
    {
    public:

        void revise(z3::expression const& key, z3::expression value);
        void reset();

        z3::expression const& operator[](z3::expression const& key) const;
    };
}
