#pragma once

#include <functional>

#include <generic-reveng/analysis/z3/z3_ast.hpp>

namespace grev
{
    class z3_expression;
}

namespace std
{
    template <>
    struct equal_to<grev::z3_expression>
    {
        bool operator()(grev::z3_expression const& expression_1, grev::z3_expression const& expression_2) const;
    };
    template <>
    struct hash<grev::z3_expression>
    {
        std::size_t operator()(grev::z3_expression const& expresssion) const;
    };
}

namespace grev
{
    class function;
    class sort;

    class z3_expression : public z3_ast<Z3_ast>
    {
        explicit z3_expression(Z3_ast const& base);

    public:

        explicit z3_expression(std::string const& name);
        explicit z3_expression(std::uint64_t value);

        operator Z3_app() const; // NOLINT [hicpp-explicit-conversions]

        std::optional<std::uint64_t> evaluate() const;

        z3_expression operator*() const;

        z3_expression operator-() const;
        z3_expression operator~() const;

        z3_expression operator+(z3_expression const& other) const;
        z3_expression operator-(z3_expression const& other) const;
        z3_expression operator*(z3_expression const& other) const;
        z3_expression operator/(z3_expression const& other) const;
        z3_expression operator%(z3_expression const& other) const;

        z3_expression smul(z3_expression const& other) const;
        z3_expression sdiv(z3_expression const& other) const;
        z3_expression smod(z3_expression const& other) const;

        z3_expression operator<<(z3_expression const& other) const;
        z3_expression operator>>(z3_expression const& other) const;

        z3_expression operator&(z3_expression const& other) const;
        z3_expression operator|(z3_expression const& other) const;
        z3_expression operator^(z3_expression const& other) const;

        z3_expression operator==(z3_expression const& other) const;
        z3_expression operator<(z3_expression const& other) const;

    private:

        static sort unique_sort();

        static function dereference_function();
    };
}
