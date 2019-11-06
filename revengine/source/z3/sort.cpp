#include <climits>
#include <cstdint>
#include <type_traits>

#include <revengine/z3/context.hpp>
#include <revengine/z3/sort.hpp>

namespace rev::z3
{
    sort::sort(Z3_sort const& base) :
        ast(base) { }

    sort const& sort::bv_64()
    {
        static sort const bv_64(Z3_mk_bv_sort(context::instance(), sizeof(std::uint64_t) * CHAR_BIT));
        return bv_64;
    }
}

static_assert(std::is_destructible_v<rev::z3::sort>);

static_assert(!std::is_copy_constructible_v<rev::z3::sort>);
static_assert(!std::is_copy_assignable_v<rev::z3::sort>);

static_assert(!std::is_move_constructible_v<rev::z3::sort>);
static_assert(!std::is_move_assignable_v<rev::z3::sort>);
