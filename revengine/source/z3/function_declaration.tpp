#include "sort.hpp"

#ifdef LINT
#include "function_declaration.hpp"
#endif

namespace rev::z3
{
    template <std::size_t RangeSize, std::size_t... DomainSizes>
    function_declaration function_declaration::bit_vector_function(std::string const& name)
    {
        std::array const domain { sort::bit_vector<DomainSizes>().native()... };

        return function_declaration(
            Z3_mk_func_decl(
                context(),
                Z3_mk_string_symbol(context(), name.c_str()),
                domain.size(),
                domain.data(),
                sort::bit_vector<RangeSize>().native()));
    }
}
