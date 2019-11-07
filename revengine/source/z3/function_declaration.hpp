#pragma once

#include <revengine/z3/ast.hpp>

namespace rev::z3
{
    class function_declaration : public ast<Z3_func_decl>
    {
        using ast<Z3_func_decl>::ast;

    public:

        template <std::size_t RangeSize, std::size_t... DomainSizes>
        static function_declaration bit_vector_function(std::string const& name);
    };
}

#ifndef LINT
#include "function_declaration.tpp"
#endif
