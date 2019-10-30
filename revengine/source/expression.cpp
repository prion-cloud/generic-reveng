#include <climits>

#include <revengine/expression.hpp>

namespace std // NOLINT [cert-dcl58-cpp]
{
    bool equal_to<rev::expression>::operator()(rev::expression const& expression_1, rev::expression const& expression_2) const
    {
        constexpr hash<rev::expression> hash;
        return hash(expression_1) == hash(expression_2);
    }
    std::size_t hash<rev::expression>::operator()(rev::expression const& expression) const
    {
        return Z3_get_ast_hash(rev::expression::context(), expression);
    }
}

namespace rev
{
    Z3_context expression::context_ = // NOLINT [cert-err58-cpp] TODO std::shared_ptr<z3::context> (?)
        Z3_mk_context({ });
    Z3_sort expression::sort_ = // NOLINT [cert-err58-cpp]
        Z3_mk_bv_sort(context_, sizeof(std::uint64_t) * CHAR_BIT);

    Z3_func_decl expression::mem_ = // NOLINT [cert-err58-cpp]
        Z3_mk_func_decl(context_, Z3_mk_string_symbol(context_, "[]"), 1, &sort_, sort_);

    expression::expression(Z3_ast const& ast) :
        ast_(Z3_simplify(context_, ast))
    {
        if (std::uint64_t value; Z3_get_numeral_uint64(context_, ast_, &value))
            value_ = value;
    }

    expression::operator Z3_ast() const
    {
        return ast_;
    }
    expression::operator bool() const
    {
        return value_.has_value();
    }

    std::uint64_t expression::operator*() const
    {
        return value_.value();
    }

    std::unordered_set<expression> expression::decompose() const
    {
        static auto const mem_hash = Z3_get_ast_hash(context_, Z3_func_decl_to_ast(context_, mem_));

        auto const app = Z3_to_app(context_, ast_);
        auto const app_decl = Z3_get_app_decl(context_, app);
        auto const app_decl_hash = Z3_get_ast_hash(context_, Z3_func_decl_to_ast(context_, app_decl));

        if (app_decl_hash == mem_hash)
            return { *this };

        std::size_t const argument_count = Z3_get_app_num_args(context_, app);

        if (argument_count == 0)
        {
            if (Z3_is_numeral_ast(context_, ast_))
                return { };

            return { *this };
        }

        std::unordered_set<expression> unknowns;
        for (std::size_t argument_index = 0; argument_index < argument_count; ++argument_index)
            unknowns.merge(expression(Z3_get_app_arg(context_, app, argument_index)).decompose());

        return unknowns;
    }

    void expression::resolve(expression const& x, expression const& y)
    {
        *this = Z3_substitute(context_, ast_, 1, &x.ast_, &y.ast_);
    }

    expression expression::mem() const
    {
        return Z3_mk_app(context_, mem_, 1, &ast_);
    }

    expression expression::operator-() const
    {
        return Z3_mk_bvneg(context_, ast_);
    }
    expression expression::operator~() const
    {
        return Z3_mk_bvnot(context_, ast_);
    }

    expression expression::operator+(expression const& other) const
    {
        return Z3_mk_bvadd(context_, ast_, other);
    }
    expression expression::operator-(expression const& other) const
    {
        return Z3_mk_bvsub(context_, ast_, other);
    }
    expression expression::operator*(expression const& other) const
    {
        return Z3_mk_bvmul(context_, ast_, other);
    }
    expression expression::operator/(expression const& other) const
    {
        return Z3_mk_bvsdiv(context_, ast_, other);
    }
    expression expression::operator%(expression const& other) const
    {
        return Z3_mk_bvsmod(context_, ast_, other);
    }

    expression expression::operator<<(expression const& other) const
    {
        return Z3_mk_bvshl(context_, ast_, other);
    }
    expression expression::operator>>(expression const& other) const
    {
        return Z3_mk_bvlshr(context_, ast_, other);
    }

    expression expression::operator&(expression const& other) const
    {
        return Z3_mk_bvand(context_, ast_, other);
    }
    expression expression::operator|(expression const& other) const
    {
        return Z3_mk_bvor(context_, ast_, other);
    }
    expression expression::operator^(expression const& other) const
    {
        return Z3_mk_bvxor(context_, ast_, other);
    }

    expression expression::operator==(expression const& other) const
    {
        return bool_value(Z3_mk_eq(context_, ast_, other));
    }
    expression expression::operator<(expression const& other) const
    {
        return bool_value(Z3_mk_bvslt(context_, ast_, other));
    }

    Z3_context const& expression::context()
    {
        return context_;
    }

    expression expression::unknown(std::string const& name)
    {
        return Z3_mk_const(context_, Z3_mk_string_symbol(context_, name.c_str()), sort_);
    }
    expression expression::value(std::uint64_t const value)
    {
        return Z3_mk_int(context_, value, sort_);
    }

    Z3_ast expression::bool_value(Z3_ast const& ast)
    {
        return Z3_mk_ite(context_, ast, Z3_mk_int(context_, 1, sort_), Z3_mk_int(context_, 0, sort_));
    }

    static_assert(std::is_destructible_v<expression>);

    static_assert(std::is_move_constructible_v<expression>);
    static_assert(std::is_move_assignable_v<expression>);

    static_assert(std::is_copy_constructible_v<expression>);
    static_assert(std::is_copy_assignable_v<expression>);
}
