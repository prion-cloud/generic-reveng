#pragma once

#include <z3.h>

namespace rev::z3
{
    class expression;

    class context
    {
        Z3_context base_;

        context();

    public:

        ~context();

        context(context const& other) = delete;
        context& operator=(context const& other) = delete;

        operator Z3_context() const;

        static context const& instance();
    };
}
