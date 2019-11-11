#include "sort.hpp"

namespace rev::z3
{
    sort::sort(std::size_t const size) :
        ast(Z3_mk_bv_sort(context(), size)) { }
}

static_assert(std::is_destructible_v<rev::z3::sort>);

static_assert(std::is_copy_constructible_v<rev::z3::sort>);
static_assert(std::is_copy_assignable_v<rev::z3::sort>);

static_assert(std::is_move_constructible_v<rev::z3::sort>);
static_assert(std::is_move_assignable_v<rev::z3::sort>);
