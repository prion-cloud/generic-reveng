#pragma once

#include <generic-reveng/analysis/z3/z3_ast.hpp>

namespace grev
{
    class sort : public z3_ast<Z3_sort>
    {
    public:

        explicit sort(std::size_t size);
    };
}
