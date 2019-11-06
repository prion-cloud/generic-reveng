#include <revengine/z3/context.hpp>
#include <revengine/z3/sort.hpp>

#ifdef LINT
#include <revengine/z3/function_declaration.hpp>
#endif

namespace rev::z3
{
    template <std::size_t RangeSize, std::size_t... DomainSizes>
    function_declaration const& function_declaration::bit_vector_function(std::string const& name)
    {
        static std::array const domain { sort::bit_vector<DomainSizes>().base()... };

        static function_declaration const bit_vector_function(
            Z3_mk_func_decl(
                context::instance(),
                Z3_mk_string_symbol(context::instance(), name.c_str()),
                domain.size(),
                domain.data(),
                sort::bit_vector<RangeSize>().base()));
        return bit_vector_function;
    }
}
