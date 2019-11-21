#pragma once

#include <z3.h>

namespace grev::z3
{
    class syntax_tree_base
    {
    protected:

        syntax_tree_base();

    public:

        static Z3_context const& context();
    };
}
