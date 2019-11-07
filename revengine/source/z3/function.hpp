#pragma once

#include <revengine/z3/expression.hpp>

#include "sort.hpp"

namespace rev::z3
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
