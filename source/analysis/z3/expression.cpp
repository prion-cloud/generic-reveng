#include <generic-reveng/analysis/z3/context.hpp>
#include <generic-reveng/analysis/z3/expression.hpp>
#include <generic-reveng/analysis/z3/sort.hpp>

namespace grev::z3
{
    expression::expression(Z3_ast const& base) :
        syntax_tree(Z3_simplify(context(), base)) { }

    expression::expression(std::string const& name) :
        syntax_tree(Z3_mk_const(context(), Z3_mk_string_symbol(context(), name.c_str()), sort())) { }
    expression::expression(std::uint32_t const value) :
        syntax_tree(Z3_mk_unsigned_int(context(), value, sort())) { }

    std::optional<std::uint32_t> expression::evaluate() const
    {
        if (std::uint32_t value; Z3_get_numeral_uint(context(), base(), &value))
            return value;

        return std::nullopt;
    }

    std::unordered_set<expression> expression::dependencies() const
    {
        if (dereferenced())
            return { *this };

        std::size_t const argument_count = Z3_get_app_num_args(context(), application());

        if (argument_count == 0)
        {
            if (Z3_is_numeral_ast(context(), base()))
                return { };

            return { *this };
        }

        std::unordered_set<expression> dependencies;
        for (std::size_t argument_index = 0; argument_index < argument_count; ++argument_index)
            dependencies.merge(expression(Z3_get_app_arg(context(), application(), argument_index)).dependencies());

        return dependencies;
    }
    expression expression::resolve_dependency(expression const& dependency, expression const& value) const
    {
        if (value == dependency)
            return *this;

        return expression(Z3_substitute(context(), base(), 1, &dependency.base(), &value.base()));
    }

    std::optional<expression> expression::reference() const
    {
        if (dereferenced())
            return expression(Z3_get_app_arg(context(), application(), 0));

        return std::nullopt;
    }
    expression expression::dereference() const
    {
        return expression(Z3_mk_app(context(), dereference_function(), 1, &base()));
    }

    expression expression::equals(expression const& other) const
    {
        return expression(
            Z3_mk_ite(context(),
                Z3_mk_eq(context(), base(), other.base()),
                expression{1}.base(),
                expression{+0}.base()));
    }
    expression expression::less_than(expression const& other) const
    {
        return expression(
            Z3_mk_ite(context(),
                Z3_mk_bvult(context(), base(), other.base()),
                expression{1}.base(),
                expression{+0}.base()));
    }

    expression expression::operator-() const
    {
        return expression(Z3_mk_bvneg(context(), base()));
    }
    expression expression::operator~() const
    {
        return expression(Z3_mk_bvnot(context(), base()));
    }

    expression& expression::operator+=(expression const& other)
    {
        return *this = expression(Z3_mk_bvadd(context(), base(), other.base()));
    }
    expression& expression::operator-=(expression const& other)
    {
        return *this = expression(Z3_mk_bvsub(context(), base(), other.base()));
    }
    expression& expression::operator*=(expression const& other)
    {
        // TODO Signed/unsigned?
        return *this = expression(Z3_mk_bvmul(context(), base(), other.base()));
    }
    expression& expression::operator/=(expression const& other)
    {
        return *this = expression(Z3_mk_bvudiv(context(), base(), other.base()));
    }
    expression& expression::operator%=(expression const& other)
    {
        // TODO Signed/unsigned?
        return *this = expression(Z3_mk_bvsmod(context(), base(), other.base()));
    }

    expression& expression::operator&=(expression const& other)
    {
        return *this = expression(Z3_mk_bvand(context(), base(), other.base()));
    }
    expression& expression::operator|=(expression const& other)
    {
        return *this = expression(Z3_mk_bvor(context(), base(), other.base()));
    }
    expression& expression::operator^=(expression const& other)
    {
        return *this = expression(Z3_mk_bvxor(context(), base(), other.base()));
    }

    expression& expression::operator<<=(expression const& other)
    {
        return *this = expression(Z3_mk_bvshl(context(), base(), other.base()));
    }
    expression& expression::operator>>=(expression const& other)
    {
        return *this = expression(Z3_mk_bvlshr(context(), base(), other.base()));
    }

    Z3_app expression::application() const
    {
        return Z3_to_app(context(), base());
    }

    bool expression::dereferenced() const
    {
        return Z3_is_eq_func_decl(context(), Z3_get_app_decl(context(), application()), dereference_function());
    }

    Z3_func_decl const& expression::dereference_function()
    {
        class dereference_function : public syntax_tree<_Z3_func_decl>
        {
        public:

            dereference_function() :
                syntax_tree(Z3_mk_func_decl(context(), Z3_mk_string_symbol(context(), "deref"), 1, &sort(), sort())) { }
            ~dereference_function() override = default;

            dereference_function(dereference_function const&) = delete;
            dereference_function(dereference_function&&) = delete;

            dereference_function& operator=(dereference_function const&) = delete;
            dereference_function& operator=(dereference_function&&) = delete;
        }
        static const dereference_function;
        return dereference_function.base();
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
