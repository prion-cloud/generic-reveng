#include <grev/z3/context.hpp>
#include <grev/z3/syntax_tree.hpp>

namespace grev::z3
{
    template <>
    syntax_tree<_Z3_ast>::operator Z3_ast() const
    {
        return base_;
    }
    template <>
    syntax_tree<_Z3_func_decl>::operator Z3_ast() const
    {
        return Z3_func_decl_to_ast(context(), base_);
    }
    template <>
    syntax_tree<_Z3_sort>::operator Z3_ast() const
    {
        return Z3_sort_to_ast(context(), base_);
    }
}
