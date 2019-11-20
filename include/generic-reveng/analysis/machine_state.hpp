#pragma once

#include <generic-reveng/analysis/z3/z3_expression.hpp>

namespace grev
{
    class machine_state :
        std::unordered_map<z3_expression, z3_expression>
    {
    public:

        void revise(z3_expression key, z3_expression value);

        z3_expression const& operator[](z3_expression const& key) const;
    };
}
