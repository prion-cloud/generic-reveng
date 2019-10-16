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

    z3::context context_ { }; // TODO std::shared_ptr<z3::context>

    expression::expression(z3::expr const& base) :
        z3::expr(base.simplify()) { }

    expression::expression(std::string const& name) :
        expression(context_.bv_const(name.c_str(), bv_size_)) { }
    expression::expression(std::uint64_t const value) :
        expression(context_.bv_val(value, bv_size_)) { }

    std::optional<std::uint64_t> expression::evaluate() const
    {
        std::uint64_t value;
        if (is_numeral_u64(value))
            return value;

        return std::nullopt;
    }

//    std::unordered_set<expression> expression::foo() const
//    {
//        // TODO mem app
//
//        if (!is_app())
//            throw std::logic_error("Unexpected expression kind");
//
//        auto const argument_count = num_args();
//
//        if (argument_count == 0)
//            return { *this };
//
//        std::unordered_set<expression> f;
//        for (auto argument_index = 0; argument_index < argument_count; ++argument_index)
//            f.merge(expression(arg(argument_index)).foo());
//
//        return f;
//    }
//    expression expression::substitute(std::vector<std::pair<expression, expression>> const& x) const
//    {
//        z3::expr_vector v_a(context_);
//        z3::expr_vector v_b(context_);
//        for (auto const& [a, b] : x)
//        {
//            v_a.push_back(a);
//            v_b.push_back(b);
//        }
//
//        z3::expr base = *this;
//        base.substitute(v_a, v_b);
//
//        return expression(base);
//    }

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
