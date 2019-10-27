#include <climits>

#include <revengine/expression.hpp>
#include <revengine/expression_composition.hpp>

namespace std // NOLINT [cert-dcl58-cpp]
{
    bool equal_to<rev::expression>::operator()(rev::expression const& expression_1, rev::expression const& expression_2) const
    {
        constexpr hash<rev::expression> hash;
        return hash(expression_1) == hash(expression_2);
    }
    std::size_t hash<rev::expression>::operator()(rev::expression const& expression) const
    {
        return Z3_get_ast_hash(rev::expression::context_, expression.ast_);
    }
}

namespace rev
{
    Z3_context expression::context_ = Z3_mk_context({ }); // TODO std::shared_ptr<z3::context>
    Z3_sort expression::sort_ = Z3_mk_bv_sort(context_, sizeof(std::uint64_t) * CHAR_BIT);

    Z3_func_decl expression::mem_ = // NOLINT [cert-err58-cpp]
        Z3_mk_func_decl(context_, Z3_mk_string_symbol(context_, "bvmem"), 1, &sort_, sort_);

    expression::expression(Z3_ast const& ast) :
        ast_(Z3_simplify(context_, ast)) { }

    void expression::resolve(expression const& x, expression const& y)
    {
        ast_ = Z3_simplify(context_, Z3_substitute(context_, ast_, 1, &x.ast_, &y.ast_));
    }
    void expression::resolve(expression_composition const& c)
    {
        std::vector<Z3_ast> source;
        std::vector<Z3_ast> destination;

        auto const unknowns = decompose();

        source.reserve(unknowns.size());
        destination.reserve(unknowns.size());

        for (auto const& unknown : unknowns)
        {
            source.push_back(unknown.ast_);
            destination.push_back(c[unknown].ast_);
        }

        ast_ = Z3_simplify(context_, Z3_substitute(context_, ast_, unknowns.size(), source.data(), destination.data()));
    }

    std::string expression::str() const
    {
        return Z3_ast_to_string(context_, ast_);
    }

    std::optional<std::uint64_t> expression::evaluate() const
    {
        std::uint64_t value;
        if (Z3_get_numeral_uint64(context_, ast_, &value))
            return value;

        return std::nullopt;
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

    expression expression::mem() const
    {
        return expression(Z3_mk_app(context_, mem_, 1, &ast_));
    }

    expression expression::operator-() const
    {
        return expression(Z3_mk_bvneg(context_, ast_));
    }
    expression expression::operator~() const
    {
        return expression(Z3_mk_bvnot(context_, ast_));
    }

    expression expression::operator+(expression const& other) const
    {
        return expression(Z3_mk_bvadd(context_, ast_, other.ast_));
    }
    expression expression::operator-(expression const& other) const
    {
        return expression(Z3_mk_bvsub(context_, ast_, other.ast_));
    }
    expression expression::operator*(expression const& other) const
    {
        return expression(Z3_mk_bvmul(context_, ast_, other.ast_));
    }
    expression expression::operator/(expression const& other) const
    {
        return expression(Z3_mk_bvsdiv(context_, ast_, other.ast_));
    }
    expression expression::operator%(expression const& other) const
    {
        return expression(Z3_mk_bvsmod(context_, ast_, other.ast_));
    }

    expression expression::operator<<(expression const& other) const
    {
        return expression(Z3_mk_bvshl(context_, ast_, other.ast_));
    }
    expression expression::operator>>(expression const& other) const
    {
        return expression(Z3_mk_bvlshr(context_, ast_, other.ast_));
    }

    expression expression::operator&(expression const& other) const
    {
        return expression(Z3_mk_bvand(context_, ast_, other.ast_));
    }
    expression expression::operator|(expression const& other) const
    {
        return expression(Z3_mk_bvor(context_, ast_, other.ast_));
    }
    expression expression::operator^(expression const& other) const
    {
        return expression(Z3_mk_bvxor(context_, ast_, other.ast_));
    }

    expression expression::operator==(expression const& other) const
    {
        return expression(bool_value(Z3_mk_eq(context_, ast_, other.ast_)));
    }
    expression expression::operator<(expression const& other) const
    {
        return expression(bool_value(Z3_mk_bvslt(context_, ast_, other.ast_)));
    }

    expression expression::unknown(std::string const& name)
    {
        return expression(Z3_mk_const(context_, Z3_mk_string_symbol(context_, name.c_str()), sort_));
    }
    expression expression::value(std::uint64_t const value)
    {
        return expression(Z3_mk_int(context_, value, sort_));
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
