#include "function.hpp"

namespace grev::z3
{
    function::function(expression const& expression) :
        syntax_tree(Z3_get_app_decl(context(), expression)) { }

    function::function(std::string const& name, std::vector<sort> const& domain, sort const& range) :
        syntax_tree(make(name, domain, range)) { }

    Z3_func_decl function::make(std::string const& name, std::vector<sort> const& domain, sort const& range)
    {
        std::vector<Z3_sort> native_domain(domain.size());
        std::transform(domain.begin(), domain.end(), native_domain.begin(), [](auto const& sort) { return sort; });

        return Z3_mk_func_decl(context(),
            Z3_mk_string_symbol(context(), name.c_str()),
            native_domain.size(),
            native_domain.data(),
            range);
    }
}

static_assert(std::is_destructible_v<grev::z3::function>);

static_assert(std::is_copy_constructible_v<grev::z3::function>);
static_assert(std::is_nothrow_move_constructible_v<grev::z3::function>);

static_assert(std::is_copy_assignable_v<grev::z3::function>);
static_assert(std::is_nothrow_move_assignable_v<grev::z3::function>);