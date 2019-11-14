#pragma once

#include <generic-reveng/analysis/z3/expression.hpp>

#include "sort.hpp"

namespace grev
{
    class function : public ast<Z3_func_decl>
    {
    public:

        explicit function(expression const& expression);

        function(std::string const& name, std::vector<sort> const& domain, sort const& range);

    private:

        static Z3_func_decl make(std::string const& name, std::vector<sort> const& domain, sort const& range);
    };
}
