#pragma once

#include <unordered_set>

#include <revengine/z3/ast.hpp>

namespace rev::z3
{
    class function;
    class sort;

    class expression : public ast<Z3_ast>
    {
        explicit expression(Z3_ast const& base);

    public:

        explicit expression(std::string const& name);
        explicit expression(std::uint64_t value);

        operator Z3_app() const;

        std::optional<std::uint64_t> evaluate() const;

        std::unordered_set<expression, expression::hash, expression::equal_to> /*TODO replace*/ decompose() const;

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

        static sort unique_sort();

        static function dereference_function();
    };
}
