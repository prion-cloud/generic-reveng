#pragma once

#include <z3.h>

#include <revengine/z3/ast.hpp>

namespace rev::z3
{
    class sort : public ast<Z3_sort>
    {
        explicit sort(Z3_sort const& base);

    public:

        sort(sort const& other) = delete;
        sort& operator=(sort const& other) = delete;

        static sort const& bv_64();
    };
}
