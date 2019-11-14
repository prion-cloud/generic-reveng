#pragma once

#include <functional>

#include <generic-reveng/analysis/z3/ast.hpp>

namespace grev
{
    class expression;
}

namespace std
{
    template <>
    struct equal_to<grev::expression>
    {
        bool operator()(grev::expression const& expression_1, grev::expression const& expression_2) const;
    };
    template <>
    struct hash<grev::expression>
    {
        std::size_t operator()(grev::expression const& expresssion) const;
    };
}

namespace grev
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
