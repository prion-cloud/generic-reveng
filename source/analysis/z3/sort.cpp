#include "sort.hpp"

namespace grev::z3
{
    sort::sort(std::size_t const size) :
        syntax_tree(Z3_mk_bv_sort(context(), size)) { }
}

static_assert(std::is_destructible_v<grev::z3::sort>);

static_assert(std::is_copy_constructible_v<grev::z3::sort>);
static_assert(std::is_nothrow_move_constructible_v<grev::z3::sort>);

static_assert(std::is_copy_assignable_v<grev::z3::sort>);
static_assert(std::is_nothrow_move_assignable_v<grev::z3::sort>);
