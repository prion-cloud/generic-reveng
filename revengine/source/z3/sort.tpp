#ifdef LINT
#include "sort.hpp"
#endif

namespace rev::z3
{
    template <std::size_t Size>
    sort sort::bit_vector()
    {
        return sort(Z3_mk_bv_sort(context(), Size));
    }
}

#ifdef LINT
template rev::z3::sort rev::z3::sort::bit_vector<64>();
#endif
