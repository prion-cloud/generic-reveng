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

        std::unordered_set<std::uint32_t> memory_dependencies() const; // TODO Store as field (?)

        void resolve(execution_fork* fork) const;
        void resolve(execution_state* state) const;

        z3::expression const& operator[](z3::expression const& key) const;

        execution_state operator+=(execution_state);

    private:

        void resolve(z3::expression* expression) const;
    };

    execution_state operator+(execution_state, execution_state);
}
