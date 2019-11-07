#include <climits>

#include <revengine/z3/expression.hpp>

#include "function_declaration.hpp"
#include "sort.hpp"

namespace rev::z3
{
    constexpr std::size_t size = sizeof(std::uint64_t) * CHAR_BIT;

    function_declaration const& dereference_function()
    {
        static auto const dereference_function = function_declaration::bit_vector_function<size, size>("deref");
        return dereference_function;
    }

    template <>
    Z3_ast ast<Z3_ast>::ast_native() const
    {
        return native_;
    }

    expression::expression(Z3_ast const& native) :
        ast(Z3_simplify(context(), native)) { }

    expression::expression(std::string const& name) :
        expression(Z3_mk_const(context(), Z3_mk_string_symbol(context(), name.c_str()), sort::bit_vector<size>())) { }
    expression::expression(std::uint64_t const value) :
        expression(Z3_mk_int(context(), value, sort::bit_vector<size>())) { }

    std::optional<std::uint64_t> expression::evaluate() const
    {
        if (std::uint64_t value; Z3_get_numeral_uint64(context(), *this, &value))
            return value;

        return std::nullopt;
    }

    std::unordered_set<expression, expression::hasher, expression::comparator> expression::decompose() const
    {
        static auto const mem_hash = function_declaration::hash(dereference_function());

        auto const app = Z3_to_app(context(), *this);
        auto const app_decl = Z3_get_app_decl(context(), app);
        auto const app_decl_hash = Z3_get_ast_hash(context(), Z3_func_decl_to_ast(context(), app_decl));

        if (app_decl_hash == mem_hash)
            return { *this };

        std::size_t const argument_count = Z3_get_app_num_args(context(), app);

        if (argument_count == 0)
        {
            if (Z3_is_numeral_ast(context(), *this))
                return { };

            return { *this };
        }

        std::unordered_set<expression, hasher, comparator> unknowns;
        for (std::size_t argument_index = 0; argument_index < argument_count; ++argument_index)
            unknowns.merge(expression(Z3_get_app_arg(context(), app, argument_index)).decompose());

        return unknowns;
    }

    expression expression::resolve(expression const& x, expression const& y) const
    {
        Z3_ast const& native_x = x;
        Z3_ast const& native_y = y;
        return expression(Z3_substitute(context(), *this, 1, &native_x, &native_y));
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
        return expression(Z3_mk_eq(context(), *this, other)).ite();
    }
    expression expression::operator<(expression const& other) const
    {
        return expression(Z3_mk_bvult(context(), *this, other)).ite();
    }

    expression expression::ite() const
    {
        expression const t(1UL);
        expression const e(0UL);

        return expression(Z3_mk_ite(context(), *this, t, e));
    }
}

static_assert(std::is_destructible_v<rev::z3::expression>);

static_assert(std::is_copy_constructible_v<rev::z3::expression>);
static_assert(std::is_copy_assignable_v<rev::z3::expression>);

static_assert(std::is_move_constructible_v<rev::z3::expression>);
static_assert(std::is_move_assignable_v<rev::z3::expression>);
