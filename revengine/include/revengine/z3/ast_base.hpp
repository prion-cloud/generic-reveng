#pragma once

#include <z3.h>

namespace rev::z3
{
    class ast_base
    {
    protected:

        ast_base();

    public:

        static Z3_context const& context();
    };
}
