#include <generic-reveng/analysis/z3/context.hpp>
#include <generic-reveng/analysis/z3/sort.hpp>
#include <generic-reveng/analysis/z3/syntax_tree.hpp>

namespace grev::z3
{
    Z3_sort const& sort(unsigned const width)
    {
        class sort : public syntax_tree<_Z3_sort>
        {
        public:

            explicit sort(unsigned const width) :
                syntax_tree(Z3_mk_bv_sort(context(), width)) { }
            ~sort() override = default;

            sort(sort const&) = delete;
            sort(sort&&) = delete;

            sort& operator=(sort const&) = delete;
            sort& operator=(sort&&) = delete;
        }
        static const sort1{1}, sort7{7}, sort8{8}, sort15{15}, sort16{16}, sort31{31}, sort32{32};

        // TODO
        switch (width)
        {
        case 1:
            return sort1.base();
        case 7:
            return sort7.base();
        case 8:
            return sort8.base();
        case 15:
            return sort15.base();
        case 16:
            return sort16.base();
        case 31:
            return sort31.base();
        case 32:
            return sort32.base();
        default:
            throw std::logic_error("Unexpected width");
        }
    }
}
