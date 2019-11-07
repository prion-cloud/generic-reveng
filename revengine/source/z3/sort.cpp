#include "sort.hpp"

namespace rev::z3
{
    sort::sort(std::size_t const size) :
        ast(Z3_mk_bv_sort(context(), size)) { }

    template <>
    Z3_ast ast<Z3_sort>::ast_native() const
    {
        return Z3_sort_to_ast(context(), *this);
    }
}

static_assert(std::is_destructible_v<rev::z3::sort>);

static_assert(std::is_copy_constructible_v<rev::z3::sort>);
static_assert(std::is_copy_assignable_v<rev::z3::sort>);

static_assert(std::is_move_constructible_v<rev::z3::sort>);
static_assert(std::is_move_assignable_v<rev::z3::sort>);
