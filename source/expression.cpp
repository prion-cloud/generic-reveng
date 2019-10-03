#include <decompilation/expression.hpp>

namespace std // NOLINT [cert-dcl58-cpp]
{
    bool equal_to<dec::expression>::operator()(dec::expression const& expression_1, dec::expression const& expression_2) const
    {
        return expression_1 == expression_2;
    }
    std::size_t hash<dec::expression>::operator()(dec::expression const& expression) const
    {
        return expression.hash();
    }
}

namespace dec
{
    constexpr std::size_t bv_size_ = sizeof(std::uint64_t) * CHAR_BIT;

    z3::context expression::context_ { };

    expression::expression(z3::expr const& base) :
        z3::expr(base.simplify()) { }

    expression::expression(std::string const& variable) :
        expression(context_.bv_const(variable.c_str(), bv_size_)) { }
    expression::expression(std::uint64_t const value) :
        expression(context_.bv_val(value, bv_size_)) { }

    std::optional<std::uint64_t> expression::evaluate() const
    {
        if (is_numeral())
            return get_numeral_uint64();

        return std::nullopt;
    }

    expression expression::mem() const
    {
        return expression(context_.function("bvmem", context_.bv_sort(bv_size_), context_.bv_sort(bv_size_))(*this));
    }

    expression expression::operator-() const
    {
        return expression(z3::operator-(*this));
    }
    expression expression::operator~() const
    {
        return expression(z3::operator~(*this));
    }

    expression expression::operator+(expression const& other) const
    {
        return expression(z3::operator+(*this, other));
    }
    expression expression::operator-(expression const& other) const
    {
        return expression(z3::operator-(*this, other));
    }
    expression expression::operator*(expression const& other) const
    {
        return expression(z3::operator*(*this, other));
    }
    expression expression::operator/(expression const& other) const
    {
        return expression(z3::operator/(*this, other));
    }
    expression expression::operator%(expression const& other) const
    {
        return expression(z3::mod(*this, other));
    }

    expression expression::operator&(expression const& other) const
    {
        return expression(z3::operator&(*this, other));
    }
    expression expression::operator|(expression const& other) const
    {
        return expression(z3::operator|(*this, other));
    }
    expression expression::operator^(expression const& other) const
    {
        return expression(z3::operator^(*this, other));
    }

    static_assert(std::is_destructible_v<expression>);

    static_assert(std::is_move_constructible_v<expression>);
    static_assert(std::is_move_assignable_v<expression>);

    static_assert(std::is_copy_constructible_v<expression>);
    static_assert(std::is_copy_assignable_v<expression>);
}
