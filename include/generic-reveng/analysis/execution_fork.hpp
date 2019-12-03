#pragma once

#include <generic-reveng/analysis/z3/expression.hpp>

namespace grev
{
    class execution_fork : std::unordered_map<z3::expression, z3::expression>
    {
    public:

        using std::unordered_map<z3::expression, z3::expression>::begin;
        using std::unordered_map<z3::expression, z3::expression>::end;

        using std::unordered_map<z3::expression, z3::expression>::extract;

        void jump(z3::expression condition, z3::expression destination);

        bool impasse() const;
    };
}
