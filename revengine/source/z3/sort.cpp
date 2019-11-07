#include "sort.hpp"

namespace rev::z3
{
    sort::sort(std::size_t const size) :
        ast(Z3_mk_bv_sort(context(), size)) { }

    template <>
    ast<Z3_sort>::operator Z3_ast() const
    {
        return Z3_sort_to_ast(context(), native_);
    }
}

static_assert(std::is_destructible_v<rev::z3::sort>);

static_assert(std::is_copy_constructible_v<rev::z3::sort>);
static_assert(std::is_copy_assignable_v<rev::z3::sort>);

static_assert(std::is_move_constructible_v<rev::z3::sort>);
static_assert(std::is_move_assignable_v<rev::z3::sort>);
