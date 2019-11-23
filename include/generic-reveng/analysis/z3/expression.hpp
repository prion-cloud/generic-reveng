#pragma once

#include <functional>

#include <generic-reveng/analysis/z3/syntax_tree.hpp>

namespace grev::z3
{
    class expression;
}

namespace std
{
    template <>
    struct equal_to<grev::z3::expression>
    {
        bool operator()(grev::z3::expression const& expression_1, grev::z3::expression const& expression_2) const;
    };
    template <>
    struct hash<grev::z3::expression>
    {
        std::size_t operator()(grev::z3::expression const& expresssion) const;
    };
}

namespace grev::z3
{
    class function;
    class sort;

    class expression : public syntax_tree<Z3_ast>
    {
        explicit expression(Z3_ast const& base);

    public:

        explicit expression(std::string const& name);
        explicit expression(std::uint32_t value);

        operator Z3_app() const;

        std::optional<std::uint32_t> evaluate() const;

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
