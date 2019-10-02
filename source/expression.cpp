#include <decompilation/expression.hpp>

namespace std // NOLINT [cert-dcl58-cpp]
{
    bool equal_to<dec::expression>::operator()(dec::expression const& expression_1, dec::expression const& expression_2) const
    {
        return expression_1.base_ == expression_2.base_;
    }
    std::size_t hash<dec::expression>::operator()(dec::expression const& expression) const
    {
        return expression.base_.hash();
    }
}

namespace dec
{
    constexpr std::size_t bv_size_ = sizeof(std::uint64_t) * CHAR_BIT;

    expression::expression(std::shared_ptr<z3::context> context, z3::expr const& base) :
        context_(std::move(context)),
        base_(base.simplify()),
        mem_(context_->function("bvmem", context_->bv_sort(bv_size_), context_->bv_sort(bv_size_))) { }

    expression::expression(std::shared_ptr<z3::context> const& context, std::string const& variable) :
        expression(context, context->bv_const(variable.c_str(), bv_size_)) { }
    expression::expression(std::shared_ptr<z3::context> const& context, std::uint64_t const value) :
        expression(context, context->bv_val(value, bv_size_)) { }

    std::string expression::to_string() const
    {
        return base_.to_string();
    }

    std::optional<std::uint64_t> expression::evaluate() const
    {
        if (base_.is_numeral())
            return base_.get_numeral_uint64();

        return std::nullopt;
    }

    expression expression::mem() const
    {
        return expression(context_, mem_(base_));
    }

    expression expression::operator-() const
    {
        return expression(context_, z3::operator-(base_));
    }
    expression expression::operator~() const
    {
        return expression(context_, z3::operator~(base_));
    }

    expression expression::operator+(expression const& other) const
    {
        return expression(context_, z3::operator+(base_, other.base_));
    }
    expression expression::operator-(expression const& other) const
    {
        return expression(context_, z3::operator-(base_, other.base_));
    }
    expression expression::operator*(expression const& other) const
    {
        return expression(context_, z3::operator*(base_, other.base_));
    }
    expression expression::operator/(expression const& other) const
    {
        return expression(context_, z3::operator/(base_, other.base_));
    }
    expression expression::operator%(expression const& other) const
    {
        return expression(context_, z3::mod(base_, other.base_));
    }

    expression expression::operator&(expression const& other) const
    {
        return expression(context_, z3::operator&(base_, other.base_));
    }
    expression expression::operator|(expression const& other) const
    {
        return expression(context_, z3::operator|(base_, other.base_));
    }
    expression expression::operator^(expression const& other) const
    {
        return expression(context_, z3::operator^(base_, other.base_));
    }

    static_assert(std::is_destructible_v<expression>);

    static_assert(std::is_move_constructible_v<expression>);
    static_assert(std::is_move_assignable_v<expression>);

    static_assert(std::is_copy_constructible_v<expression>);
    static_assert(std::is_copy_assignable_v<expression>);
}
