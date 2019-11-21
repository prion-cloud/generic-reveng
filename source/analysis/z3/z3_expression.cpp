#include <climits>

#include <generic-reveng/analysis/z3/z3_expression.hpp>

#include "z3_function.hpp"

namespace std // NOLINT [cert-dcl58-cpp]
{
    bool equal_to<grev::z3_expression>::operator()(grev::z3_expression const& expression_1, grev::z3_expression const& expression_2) const
    {
        static constexpr std::hash<grev::z3_expression> hash;
        return hash(expression_1) == hash(expression_2);
    }
    std::size_t hash<grev::z3_expression>::operator()(grev::z3_expression const& expression) const
    {
        return Z3_get_ast_hash(grev::z3_expression::context(), expression);
    }
}

namespace grev
{
    z3_expression::z3_expression(Z3_ast const& native) :
        z3_ast(Z3_simplify(context(), native)) { }

    z3_expression::z3_expression(std::string const& name) :
        z3_ast(Z3_mk_const(context(), Z3_mk_string_symbol(context(), name.c_str()), unique_sort())) { }
    z3_expression::z3_expression(std::uint64_t const value) :
        z3_ast(Z3_mk_unsigned_int64(context(), value, unique_sort())) { }

    z3_expression::operator Z3_app() const
    {
        return Z3_to_app(context(), *this);
    }

    std::optional<std::uint64_t> z3_expression::evaluate() const
    {
        if (std::uint64_t value; Z3_get_numeral_uint64(context(), *this, &value))
            return value;

        return std::nullopt;
    }

    z3_expression z3_expression::operator*() const
    {
        Z3_ast const& native = *this;
        return z3_expression(Z3_mk_app(context(), dereference_function(), 1, &native));
    }

    z3_expression z3_expression::operator-() const
    {
        return z3_expression(Z3_mk_bvneg(context(), *this));
    }
    z3_expression z3_expression::operator~() const
    {
        return z3_expression(Z3_mk_bvnot(context(), *this));
    }

    z3_expression z3_expression::operator+(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvadd(context(), *this, other));
    }
    z3_expression z3_expression::operator-(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvsub(context(), *this, other));
    }
    z3_expression z3_expression::operator*(z3_expression const&) const
    {
        throw std::logic_error("Not implemented"); // TODO
    }
    z3_expression z3_expression::operator/(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvudiv(context(), *this, other));
    }
    z3_expression z3_expression::operator%(z3_expression const&) const
    {
        throw std::logic_error("Not implemented"); // TODO
    }

    z3_expression z3_expression::smul(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvmul(context(), *this, other));
    }
    z3_expression z3_expression::sdiv(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvsdiv(context(), *this, other));
    }
    z3_expression z3_expression::smod(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvsmod(context(), *this, other));
    }

    z3_expression z3_expression::operator<<(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvshl(context(), *this, other));
    }
    z3_expression z3_expression::operator>>(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvlshr(context(), *this, other));
    }

    z3_expression z3_expression::operator&(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvand(context(), *this, other));
    }
    z3_expression z3_expression::operator|(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvor(context(), *this, other));
    }
    z3_expression z3_expression::operator^(z3_expression const& other) const
    {
        return z3_expression(Z3_mk_bvxor(context(), *this, other));
    }

    z3_expression z3_expression::operator==(z3_expression const& other) const
    {
        return z3_expression(
            Z3_mk_ite(context(),
                Z3_mk_eq(context(), *this, other),
                z3_expression(std::uint64_t{1}),
                z3_expression(std::uint64_t{0})));
    }
    z3_expression z3_expression::operator<(z3_expression const& other) const
    {
        return z3_expression(
            Z3_mk_ite(context(),
                Z3_mk_bvult(context(), *this, other),
                z3_expression(std::uint64_t{1}),
                z3_expression(std::uint64_t{0})));
    }

    sort z3_expression::unique_sort()
    {
        // TODO static ?
        return sort(sizeof(std::uint64_t) * CHAR_BIT);
    }

    function z3_expression::dereference_function()
    {
        // TODO static ?
        return function("deref", { unique_sort() }, unique_sort());
    }
}

static_assert(std::is_destructible_v<grev::z3_expression>);

static_assert(std::is_copy_constructible_v<grev::z3_expression>);
static_assert(std::is_nothrow_move_constructible_v<grev::z3_expression>);

static_assert(std::is_copy_assignable_v<grev::z3_expression>);
static_assert(std::is_nothrow_move_assignable_v<grev::z3_expression>);
