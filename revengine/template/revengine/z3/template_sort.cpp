#include <revengine/z3/context.hpp>

#ifdef LINT
#include <revengine/z3/sort.hpp>
#endif

namespace rev::z3
{
    template <std::size_t Size>
    sort sort::bit_vector()
    {
        static sort const bit_vector(Z3_mk_bv_sort(context::instance(), Size));
        return bit_vector;
    }
}
