#include <revengine/z3/context.hpp>
#include <revengine/z3/function_declaration.hpp>

namespace rev::z3
{
    template <>
    Z3_ast ast<Z3_func_decl>::upcast() const
    {
        return Z3_func_decl_to_ast(context::instance(), base_);
    }
}

static_assert(std::is_destructible_v<rev::z3::function_declaration>);

static_assert(std::is_copy_constructible_v<rev::z3::function_declaration>);
static_assert(std::is_copy_assignable_v<rev::z3::function_declaration>);

static_assert(std::is_move_constructible_v<rev::z3::function_declaration>);
static_assert(std::is_move_assignable_v<rev::z3::function_declaration>);
