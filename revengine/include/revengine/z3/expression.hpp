#pragma once

#include <functional>

#include <revengine/z3/ast.hpp>

namespace rev::z3
{
    class expression;
}

namespace std
{
    template <>
    struct equal_to<rev::z3::expression>
    {
        bool operator()(rev::z3::expression const& expression_1, rev::z3::expression const& expression_2) const;
    };
    template <>
    struct hash<rev::z3::expression>
    {
        std::size_t operator()(rev::z3::expression const& expresssion) const;
    };
}

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

        operator Z3_app() const; // NOLINT [hicpp-explicit-conversions]

        std::optional<std::uint64_t> evaluate() const;

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
