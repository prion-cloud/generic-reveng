#pragma once

#include <generic-reveng/analysis/z3/syntax_tree.hpp>

namespace grev::z3
{
    class sort : public syntax_tree<Z3_sort>
    {
    public:

        explicit sort(std::size_t size);
    };
}
