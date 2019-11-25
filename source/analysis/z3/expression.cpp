#include <climits>

#include <generic-reveng/analysis/z3/expression.hpp>

#include "function.hpp"

namespace std // NOLINT [cert-dcl58-cpp]
{
    bool equal_to<grev::z3::expression>::operator()(grev::z3::expression const& a, grev::z3::expression const& b) const
    {
        static constexpr std::hash<grev::z3::expression> hash;
        return hash(a) == hash(b);
    }
    std::size_t hash<grev::z3::expression>::operator()(grev::z3::expression const& expression) const
    {
        return Z3_get_ast_hash(grev::z3::expression::context(), expression);
    }
}

namespace grev::z3
{
    expression::expression(Z3_ast const& native) :
        syntax_tree(Z3_simplify(context(), native)) { }

    expression::expression(std::string const& name) :
        syntax_tree(Z3_mk_const(context(), Z3_mk_string_symbol(context(), name.c_str()), unique_sort())) { }
    expression::expression(std::uint32_t const value) :
        syntax_tree(Z3_mk_unsigned_int(context(), value, unique_sort())) { }

    expression::operator Z3_app() const
    {
        return Z3_to_app(context(), *this);
    }

    std::optional<std::uint32_t> expression::evaluate() const
    {
        if (std::uint32_t value; Z3_get_numeral_uint(context(), *this, &value))
            return value;

        return std::nullopt;
    }

    std::unordered_set<expression> expression::dependencies() const
    {
        if (dereferenced())
            return { *this };

        std::size_t const argument_count = Z3_get_app_num_args(context(), *this);

        if (argument_count == 0)
        {
            if (Z3_is_numeral_ast(context(), *this))
                return { };

            return { *this };
        }

        std::unordered_set<expression> dependencies;
        for (std::size_t argument_index = 0; argument_index < argument_count; ++argument_index)
            dependencies.merge(expression(Z3_get_app_arg(context(), *this, argument_index)).dependencies());

        return dependencies;
    }
    expression expression::resolve_dependency(expression const& dependency, expression const& value) const
    {
        Z3_ast const& native_dependency = dependency;
        Z3_ast const& native_value = value;
        return expression(Z3_substitute(context(), *this, 1, &native_dependency, &native_value));
    }

    std::optional<expression> expression::reference() const
    {
        if (dereferenced())
            return expression(Z3_get_app_arg(context(), *this, 0));

        return std::nullopt;
    }
    expression expression::dereference() const
    {
        Z3_ast const& native = *this;
        return expression(Z3_mk_app(context(), dereference_function(), 1, &native));
    }

    expression& expression::operator+=(expression const& other)
    {
        return *this = expression(Z3_mk_bvadd(context(), *this, other));
    }
    expression& expression::operator-=(expression const& other)
    {
        return *this = expression(Z3_mk_bvsub(context(), *this, other));
    }
    expression& expression::operator*=(expression const& other)
    {
        // TODO Signed/unsigned?
        return *this = expression(Z3_mk_bvmul(context(), *this, other));
    }
    expression& expression::operator/=(expression const& other)
    {
        return *this = expression(Z3_mk_bvudiv(context(), *this, other));
    }
    expression& expression::operator%=(expression const& other)
    {
        // TODO Signed/unsigned?
        return *this = expression(Z3_mk_bvsmod(context(), *this, other));
    }

    expression& expression::operator&=(expression const& other)
    {
        return *this = expression(Z3_mk_bvand(context(), *this, other));
    }
    expression& expression::operator|=(expression const& other)
    {
        return *this = expression(Z3_mk_bvor(context(), *this, other));
    }
    expression& expression::operator^=(expression const& other)
    {
        return *this = expression(Z3_mk_bvxor(context(), *this, other));
    }

    expression& expression::operator<<=(expression const& other)
    {
        return *this = expression(Z3_mk_bvshl(context(), *this, other));
    }
    expression& expression::operator>>=(expression const& other)
    {
        return *this = expression(Z3_mk_bvlshr(context(), *this, other));
    }

    expression expression::operator-() const
    {
        return expression(Z3_mk_bvneg(context(), *this));
    }
    expression expression::operator~() const
    {
        return expression(Z3_mk_bvnot(context(), *this));
    }

    expression expression::operator==(expression const& other) const
    {
        return expression(
            Z3_mk_ite(context(),
                Z3_mk_eq(context(), *this, other),
                expression(std::uint32_t{1}),
                expression(std::uint32_t{0})));
    }
    expression expression::operator<(expression const& other) const
    {
        return expression(
            Z3_mk_ite(context(),
                Z3_mk_bvult(context(), *this, other),
                expression(std::uint32_t{1}),
                expression(std::uint32_t{0})));
    }

    bool expression::dereferenced() const
    {
        return function(Z3_get_app_decl(context(), *this)).equals(dereference_function());
    }

    sort expression::unique_sort()
    {
        // TODO static ?
        return sort(sizeof(std::uint32_t) * CHAR_BIT);
    }

    function expression::dereference_function()
    {
        // TODO static ?
        return function("deref", { unique_sort() }, unique_sort());
    }

    expression operator+(expression a, expression const& b)
    {
        return a += b;
    }
    expression operator-(expression a, expression const& b)
    {
        return a -= b;
    }
    expression operator*(expression a, expression const& b)
    {
        return a *= b;
    }
    expression operator/(expression a, expression const& b)
    {
        return a /= b;
    }
    expression operator%(expression a, expression const& b)
    {
        return a %= b;
    }

    expression operator&(expression a, expression const& b)
    {
        return a &= b;
    }
    expression operator|(expression a, expression const& b)
    {
        return a |= b;
    }
    expression operator^(expression a, expression const& b)
    {
        return a ^= b;
    }

    expression operator<<(expression a, expression const& b)
    {
        return a <<= b;
    }
    expression operator>>(expression a, expression const& b)
    {
        return a >>= b;
    }
}

static_assert(std::is_destructible_v<grev::z3::expression>);

static_assert(std::is_copy_constructible_v<grev::z3::expression>);
static_assert(std::is_nothrow_move_constructible_v<grev::z3::expression>);

static_assert(std::is_copy_assignable_v<grev::z3::expression>);
static_assert(std::is_nothrow_move_assignable_v<grev::z3::expression>);
