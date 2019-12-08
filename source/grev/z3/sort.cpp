#include <grev/z3/context.hpp>
#include <grev/z3/sort.hpp>
#include <grev/z3/syntax_tree.hpp>

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
        static const sort1{1}, sort7{7}, sort8{8}, sort15{15}, sort16{16}, sort24{24}, sort31{31}, sort32{32}, sort48{48}, sort56{56}, sort63{63}, sort64{64};

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
        case 24:
            return sort24.base();
        case 31:
            return sort31.base();
        case 32:
            return sort32.base();
        case 48:
            return sort48.base();
        case 56:
            return sort56.base();
        case 63:
            return sort63.base();
        case 64:
            return sort64.base();
        default:
            throw std::logic_error("Unexpected width");
        }
    }
}
