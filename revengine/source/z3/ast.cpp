#include <revengine/z3/ast.hpp>

namespace rev::z3
{
    template <>
    ast<Z3_ast>::operator Z3_ast() const
    {
        return native_;
    }
    template <>
    ast<Z3_func_decl>::operator Z3_ast() const
    {
        return Z3_func_decl_to_ast(context(), native_);
    }
    template <>
    ast<Z3_sort>::operator Z3_ast() const
    {
        return Z3_sort_to_ast(context(), native_);
    }
}
