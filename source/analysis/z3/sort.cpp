#include <climits>

#include <generic-reveng/analysis/z3/context.hpp>
#include <generic-reveng/analysis/z3/sort.hpp>
#include <generic-reveng/analysis/z3/syntax_tree.hpp>

namespace grev::z3
{
    Z3_sort const& sort()
    {
        class sort : public syntax_tree<_Z3_sort>
        {
        public:

            sort() :
                syntax_tree(Z3_mk_bv_sort(context(), sizeof(std::uint32_t) * CHAR_BIT)) { }
            ~sort() override = default;

            sort(sort const&) = delete;
            sort(sort&&) = delete;

            sort& operator=(sort const&) = delete;
            sort& operator=(sort&&) = delete;
        }
        static const sort;
        return sort.base();
    }
}
