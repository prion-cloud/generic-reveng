#pragma once

#include <unordered_map>

#include <generic-reveng/analysis/execution_fork.hpp>

namespace grev
{
    class execution_state : std::unordered_map<z3::expression, z3::expression>
    {
    public:

        using std::unordered_map<z3::expression, z3::expression>::clear;

        /*!
         *  Sets a new unbound value to a certain, possibly existing key.
         */
        void define(z3::expression key, z3::expression value);

        execution_fork resolve(execution_fork source) const;
        execution_state resolve(execution_state source) const;

        z3::expression const& operator[](z3::expression const& key) const;

    private:

        z3::expression resolve_key(z3::expression key) const;
        z3::expression resolve_value(z3::expression value) const;
    };
}
