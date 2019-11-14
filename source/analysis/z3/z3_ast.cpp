#include <generic-reveng/analysis/z3/z3_ast.hpp>

namespace grev
{
    template <>
    z3_ast<Z3_ast>::operator Z3_ast() const
    {
        return native_;
    }
    template <>
    z3_ast<Z3_func_decl>::operator Z3_ast() const
    {
        return Z3_func_decl_to_ast(context(), native_);
    }
    template <>
    z3_ast<Z3_sort>::operator Z3_ast() const
    {
        return Z3_sort_to_ast(context(), native_);
    }
}
