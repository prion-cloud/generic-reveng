#include <decompilation/expression.hpp>

bool operator==(z3::func_decl const& a, z3::func_decl const& b)
{
    return a.hash() == b.hash();
}

namespace std // NOLINT [cert-dcl58-cpp]
{
    std::size_t hash<dec::expression>::operator()(dec::expression const& expression) const
    {
        return expression.hash();
    }
}

namespace dec
{
    constexpr std::size_t bv_size_ = sizeof(std::uint64_t) * CHAR_BIT;

    z3::context context_ { }; // TODO std::shared_ptr<z3::context>

    z3::func_decl expression::mem_ = // NOLINT [cert-err58-cpp]
        context_.function("bvmem", context_.bv_sort(bv_size_), context_.bv_sort(bv_size_));

    expression::expression(z3::expr const& base) :
        z3::expr(base.simplify()) { }

    expression::expression(std::string const& name) :
        expression(context_.bv_const(name.c_str(), bv_size_)) { }
    expression::expression(std::uint64_t const value) :
        expression(context_.bv_val(value, bv_size_)) { }

    expression expression::substitute(expression const& x, expression const& y) const
    {
        z3::expr_vector v_x(context_);
        z3::expr_vector v_y(context_);
        v_x.push_back(x);
        v_y.push_back(y);

        z3::expr f = *this;
        return expression(f.substitute(v_x, v_y));
    }

    std::optional<std::uint64_t> expression::evaluate() const
    {
        std::uint64_t value;
        if (is_numeral_u64(value))
            return value;

        return std::nullopt;
    }

    std::unordered_set<expression> expression::decompose() const
    {
        if (!is_app())
            throw std::logic_error("Unexpected expression kind");

        if (decl() == mem_)
            return { *this };

        auto const argument_count = num_args();

        if (argument_count == 0)
        {
            if (is_numeral())
                return { };

            return { *this };
        }

        std::unordered_set<expression> unknowns;
        for (auto argument_index = 0; argument_index < argument_count; ++argument_index)
            unknowns.merge(expression(arg(argument_index)).decompose());

        return unknowns;
    }

    expression expression::mem() const
    {
        return expression(mem_(*this));
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

    bool expression::operator==(expression const& other) const
    {
        return hash() == other.hash();
    }
    bool expression::operator!=(expression const& other) const
    {
        return !operator==(other);
    }

    static_assert(std::is_destructible_v<expression>);

    static_assert(std::is_move_constructible_v<expression>);
    static_assert(std::is_move_assignable_v<expression>);

    static_assert(std::is_copy_constructible_v<expression>);
    static_assert(std::is_copy_assignable_v<expression>);
}
