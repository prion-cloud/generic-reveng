#include <climits>

#include <revengine/z3/expression.hpp>

#include "function.hpp"

namespace std // NOLINT [cert-dcl58-cpp]
{
    bool equal_to<rev::z3::expression>::operator()(rev::z3::expression const& expression_1, rev::z3::expression const& expression_2) const
    {
        static constexpr std::hash<rev::z3::expression> hash;
        return hash(expression_1) == hash(expression_2);
    }
    std::size_t hash<rev::z3::expression>::operator()(rev::z3::expression const& expression) const
    {
        return Z3_get_ast_hash(rev::z3::expression::context(), expression);
    }
}

namespace rev::z3
{
    expression::expression(Z3_ast const& native) :
        ast(Z3_simplify(context(), native)) { }

    expression::expression(std::string const& name) :
        ast(Z3_mk_const(context(), Z3_mk_string_symbol(context(), name.c_str()), unique_sort())) { }
    expression::expression(std::uint64_t const value) :
        ast(Z3_mk_unsigned_int64(context(), value, unique_sort())) { }

    expression::operator Z3_app() const
    {
        return Z3_to_app(context(), *this);
    }

    std::optional<std::uint64_t> expression::evaluate() const
    {
        if (std::uint64_t value; Z3_get_numeral_uint64(context(), *this, &value))
            return value;

        return std::nullopt;
    }

    expression expression::operator*() const
    {
        Z3_ast const& native = *this;
        return expression(Z3_mk_app(context(), dereference_function(), 1, &native));
    }

    expression expression::operator-() const
    {
        return expression(Z3_mk_bvneg(context(), *this));
    }
    expression expression::operator~() const
    {
        return expression(Z3_mk_bvnot(context(), *this));
    }

    expression expression::operator+(expression const& other) const
    {
        return expression(Z3_mk_bvadd(context(), *this, other));
    }
    expression expression::operator-(expression const& other) const
    {
        return expression(Z3_mk_bvsub(context(), *this, other));
    }
    expression expression::operator*(expression const&) const
    {
        throw std::logic_error("Not implemented"); // TODO
    }
    expression expression::operator/(expression const& other) const
    {
        return expression(Z3_mk_bvudiv(context(), *this, other));
    }
    expression expression::operator%(expression const&) const
    {
        throw std::logic_error("Not implemented"); // TODO
    }

    expression expression::smul(expression const& other) const
    {
        return expression(Z3_mk_bvmul(context(), *this, other));
    }
    expression expression::sdiv(expression const& other) const
    {
        return expression(Z3_mk_bvsdiv(context(), *this, other));
    }
    expression expression::smod(expression const& other) const
    {
        return expression(Z3_mk_bvsmod(context(), *this, other));
    }

    expression expression::operator<<(expression const& other) const
    {
        return expression(Z3_mk_bvshl(context(), *this, other));
    }
    expression expression::operator>>(expression const& other) const
    {
        return expression(Z3_mk_bvlshr(context(), *this, other));
    }

    expression expression::operator&(expression const& other) const
    {
        return expression(Z3_mk_bvand(context(), *this, other));
    }
    expression expression::operator|(expression const& other) const
    {
        return expression(Z3_mk_bvor(context(), *this, other));
    }
    expression expression::operator^(expression const& other) const
    {
        return expression(Z3_mk_bvxor(context(), *this, other));
    }

    expression expression::operator==(expression const& other) const
    {
        return expression(
            Z3_mk_ite(context(),
                Z3_mk_eq(context(), *this, other),
                expression(std::uint64_t{1}),
                expression(std::uint64_t{0})));
    }
    expression expression::operator<(expression const& other) const
    {
        return expression(
            Z3_mk_ite(context(),
                Z3_mk_bvult(context(), *this, other),
                expression(std::uint64_t{1}),
                expression(std::uint64_t{0})));
    }

    sort expression::unique_sort()
    {
        // TODO static ?
        return sort(sizeof(std::uint64_t) * CHAR_BIT);
    }

    function expression::dereference_function()
    {
        // TODO static ?
        return function("deref", { unique_sort() }, unique_sort());
    }
}

static_assert(std::is_destructible_v<rev::z3::expression>);

static_assert(std::is_copy_constructible_v<rev::z3::expression>);
static_assert(std::is_copy_assignable_v<rev::z3::expression>);

static_assert(std::is_move_constructible_v<rev::z3::expression>);
static_assert(std::is_move_assignable_v<rev::z3::expression>);
