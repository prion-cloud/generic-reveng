#pragma once

#include <revengine/z3/expression.hpp>

namespace rev
{
    class machine_impact :
        std::unordered_map<z3::expression, z3::expression, z3::expression::hash, z3::expression::equal_to>
    {
    public:

        void revise(z3::expression const& key, z3::expression const& value);

        z3::expression const& operator[](z3::expression const& key) const;
    };
}
