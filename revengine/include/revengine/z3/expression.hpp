#pragma once

#include <memory>
#include <unordered_set>

#include <revengine/z3/ast.hpp>

namespace rev::z3
{
    class expression : ast<Z3_ast>
    {
        explicit expression(Z3_ast const& base);

    public:

        explicit expression(std::string const& name);
        explicit expression(std::uint64_t value);

        std::optional<std::uint64_t> evaluate() const;

        std::unordered_set<expression> decompose() const;

        expression resolve(expression const& x, expression const& y) const;

        expression operator*() const;

        expression operator-() const;
        expression operator~() const;

        expression operator+(expression const& other) const;
        expression operator-(expression const& other) const;
        expression operator*(expression const& other) const;
        expression operator/(expression const& other) const;
        expression operator%(expression const& other) const;

        expression smul(expression const& other) const;
        expression sdiv(expression const& other) const;
        expression smod(expression const& other) const;

        expression operator<<(expression const& other) const;
        expression operator>>(expression const& other) const;

        expression operator&(expression const& other) const;
        expression operator|(expression const& other) const;
        expression operator^(expression const& other) const;

        expression operator==(expression const& other) const;
        expression operator<(expression const& other) const;

    private:

        expression ite() const;
    };
}
