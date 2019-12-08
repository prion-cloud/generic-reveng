#pragma once

#include <unordered_map>

#include <generic-reveng/analysis/z3/expression.hpp>

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

        std::unordered_set<z3::expression> dependencies() const; // TODO Store as field

        void resolve(z3::expression* expression) const;
        void resolve(execution_state* state) const;

        z3::expression operator[](z3::expression key) const;

        execution_state operator+=(execution_state);
    };

    execution_state operator+(execution_state, execution_state);
}
