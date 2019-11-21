#include <generic-reveng/analysis/z3/syntax_tree.hpp>

namespace grev::z3
{
    template <>
    syntax_tree<Z3_ast>::operator Z3_ast() const
    {
        return native_;
    }
    template <>
    syntax_tree<Z3_func_decl>::operator Z3_ast() const
    {
        return Z3_func_decl_to_ast(context(), native_);
    }
    template <>
    syntax_tree<Z3_sort>::operator Z3_ast() const
    {
        return Z3_sort_to_ast(context(), native_);
    }
}
