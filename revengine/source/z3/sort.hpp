#pragma once

#include <revengine/z3/ast.hpp>

namespace rev::z3
{
    class sort : public ast<Z3_sort>
    {
    public:

        explicit sort(std::size_t size);
    };
}
