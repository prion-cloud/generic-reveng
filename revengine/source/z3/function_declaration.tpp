#include "sort.hpp"

#ifdef LINT
#include "function_declaration.hpp"
#endif

namespace rev::z3
{
    template <std::size_t RangeSize, std::size_t... DomainSizes>
    function_declaration function_declaration::bit_vector_function(std::string const& name)
    {
        std::array const domain { static_cast<Z3_sort>(sort::bit_vector<DomainSizes>())... };

        return function_declaration(
            Z3_mk_func_decl(
                context(),
                Z3_mk_string_symbol(context(), name.c_str()),
                domain.size(),
                domain.data(),
                sort::bit_vector<RangeSize>()));
    }
}

#ifdef LINT
template rev::z3::function_declaration rev::z3::function_declaration::bit_vector_function<64, 64>(std::string const&);
#endif
