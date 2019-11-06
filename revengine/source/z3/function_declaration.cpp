#include <type_traits>

#include <revengine/z3/context.hpp>
#include <revengine/z3/function_declaration.hpp>
#include <revengine/z3/sort.hpp>

namespace rev::z3
{
    function_declaration::function_declaration(Z3_func_decl const& base) :
        ast(base) { }

    function_declaration const& function_declaration::mem()
    {
        auto const& s = sort::bv_64();

        static function_declaration const mem(Z3_mk_func_decl(context::instance(), Z3_mk_string_symbol(context::instance(), "[]"), 1, &s.base(), s.base()));
        return mem;
    }
}

static_assert(std::is_destructible_v<rev::z3::function_declaration>);

static_assert(!std::is_copy_constructible_v<rev::z3::function_declaration>);
static_assert(!std::is_copy_assignable_v<rev::z3::function_declaration>);

static_assert(!std::is_move_constructible_v<rev::z3::function_declaration>);
static_assert(!std::is_move_assignable_v<rev::z3::function_declaration>);
