#pragma once

#include <z3.h>

namespace grev
{
    class z3_ast_base
    {
    protected:

        z3_ast_base();

    public:

        static Z3_context const& context();
    };
}
