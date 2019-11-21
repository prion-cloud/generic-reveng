#pragma once

#include <generic-reveng/analysis/z3/expression.hpp>

#include "sort.hpp"

namespace grev::z3
{
    class function : public syntax_tree<Z3_func_decl>
    {
    public:

        explicit function(expression const& expression);

        function(std::string const& name, std::vector<sort> const& domain, sort const& range);

    private:

        static Z3_func_decl make(std::string const& name, std::vector<sort> const& domain, sort const& range);
    };
}
