#include <climits>

#include <revengine/z3/context.hpp>
#include <revengine/z3/expression.hpp>
#include <revengine/z3/function_declaration.hpp>
#include <revengine/z3/sort.hpp>

namespace rev::z3
{
//    Z3_sort expression::sort_ = // NOLINT [cert-err58-cpp]
//        Z3_mk_bv_sort(context::instance(), sizeof(std::uint64_t) * CHAR_BIT);

    expression::expression(Z3_ast const& base) :
        ast(Z3_simplify(context::instance(), base)) { }

    expression::expression(std::string const& name) :
        expression(Z3_mk_const(context::instance(), Z3_mk_string_symbol(context::instance(), name.c_str()), sort::bv_64().base())) { }
    expression::expression(std::uint64_t const value) :
        expression(Z3_mk_int(context::instance(), value, sort::bv_64().base())) { }

    std::optional<std::uint64_t> expression::evaluate() const
    {
        if (std::uint64_t value; Z3_get_numeral_uint64(context::instance(), base(), &value))
            return value;

        return std::nullopt;
    }

//    std::unordered_set<expression> expression::decompose() const
//    {
//        static auto const mem_hash = Z3_get_ast_hash(context::instance(), Z3_func_decl_to_ast(context::instance(), mem_decl()));
//
//        auto const app = Z3_to_app(context::instance(), base());
//        auto const app_decl = Z3_get_app_decl(context::instance(), app);
//        auto const app_decl_hash = Z3_get_ast_hash(context::instance(), Z3_func_decl_to_ast(context::instance(), app_decl));
//
//        if (app_decl_hash == mem_hash)
//            return { *this };
//
//        std::size_t const argument_count = Z3_get_app_num_args(context::instance(), app);
//
//        if (argument_count == 0)
//        {
//            if (Z3_is_numeral_ast(context::instance(), base()))
//                return { };
//
//            return { *this };
//        }
//
//        std::unordered_set<expression> unknowns;
//        for (std::size_t argument_index = 0; argument_index < argument_count; ++argument_index)
//            unknowns.merge(expression(Z3_get_app_arg(context::instance(), app, argument_index)).decompose());
//
//        return unknowns;
//    }

    expression expression::resolve(expression const& x, expression const& y) const
    {
        return expression(Z3_substitute(context::instance(), base(), 1, &x.base(), &y.base()));
    }

    expression expression::operator*() const
    {
        return expression(Z3_mk_app(context::instance(), function_declaration::mem().base(), 1, &base()));
    }

    expression expression::operator-() const
    {
        return expression(Z3_mk_bvneg(context::instance(), base()));
    }
    expression expression::operator~() const
    {
        return expression(Z3_mk_bvnot(context::instance(), base()));
    }

    expression expression::operator+(expression const& other) const
    {
        return expression(Z3_mk_bvadd(context::instance(), base(), other.base()));
    }
    expression expression::operator-(expression const& other) const
    {
        return expression(Z3_mk_bvsub(context::instance(), base(), other.base()));
    }
    expression expression::operator*(expression const&) const
    {
        throw std::logic_error("Not implemented"); // TODO
    }
    expression expression::operator/(expression const& other) const
    {
        return expression(Z3_mk_bvudiv(context::instance(), base(), other.base()));
    }
    expression expression::operator%(expression const&) const
    {
        throw std::logic_error("Not implemented"); // TODO
    }

    expression expression::smul(expression const& other) const
    {
        return expression(Z3_mk_bvmul(context::instance(), base(), other.base()));
    }
    expression expression::sdiv(expression const& other) const
    {
        return expression(Z3_mk_bvsdiv(context::instance(), base(), other.base()));
    }
    expression expression::smod(expression const& other) const
    {
        return expression(Z3_mk_bvsmod(context::instance(), base(), other.base()));
    }

    expression expression::operator<<(expression const& other) const
    {
        return expression(Z3_mk_bvshl(context::instance(), base(), other.base()));
    }
    expression expression::operator>>(expression const& other) const
    {
        return expression(Z3_mk_bvlshr(context::instance(), base(), other.base()));
    }

    expression expression::operator&(expression const& other) const
    {
        return expression(Z3_mk_bvand(context::instance(), base(), other.base()));
    }
    expression expression::operator|(expression const& other) const
    {
        return expression(Z3_mk_bvor(context::instance(), base(), other.base()));
    }
    expression expression::operator^(expression const& other) const
    {
        return expression(Z3_mk_bvxor(context::instance(), base(), other.base()));
    }

    expression expression::operator==(expression const& other) const
    {
        return expression(Z3_mk_eq(context::instance(), base(), other.base())).ite();
    }
    expression expression::operator<(expression const& other) const
    {
        return expression(Z3_mk_bvult(context::instance(), base(), other.base())).ite();
    }

    expression expression::ite() const
    {
        expression const t(1UL);
        expression const e(0UL);

        return expression(Z3_mk_ite(context::instance(), base(), t.base(), e.base()));
    }
}

static_assert(std::is_destructible_v<rev::z3::expression>);

static_assert(std::is_move_constructible_v<rev::z3::expression>);
static_assert(std::is_move_assignable_v<rev::z3::expression>);

static_assert(std::is_copy_constructible_v<rev::z3::expression>);
static_assert(std::is_copy_assignable_v<rev::z3::expression>);
