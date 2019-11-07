#pragma once

#include <z3.h>

#include <revengine/z3/ast.hpp>

namespace rev::z3
{
    class sort : public ast<Z3_sort>
    {
        using ast<Z3_sort>::ast;

    public:

        template <std::size_t Size>
        static sort bit_vector();
    };
}

#ifndef LINT
#include "sort.tpp"
#endif
