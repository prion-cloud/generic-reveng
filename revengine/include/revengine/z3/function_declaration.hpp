#pragma once

#include <revengine/z3/ast.hpp>

namespace rev::z3
{
    class function_declaration : public ast<Z3_func_decl>
    {
        explicit function_declaration(Z3_func_decl const& base);

    public:

        function_declaration(function_declaration const& other) = delete;
        function_declaration& operator=(function_declaration const& other) = delete;

        static function_declaration const& mem();
    };
}
