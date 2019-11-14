#pragma once

#include <generic-reveng/analysis/z3/z3_expression.hpp>

#include "z3_sort.hpp"

namespace grev
{
    class function : public z3_ast<Z3_func_decl>
    {
    public:

        explicit function(z3_expression const& expression);

        function(std::string const& name, std::vector<sort> const& domain, sort const& range);

    private:

        static Z3_func_decl make(std::string const& name, std::vector<sort> const& domain, sort const& range);
    };
}
