#pragma once

#include <generic-reveng/analysis/z3/ast.hpp>

namespace grev
{
    class sort : public ast<Z3_sort>
    {
    public:

        explicit sort(std::size_t size);
    };
}
