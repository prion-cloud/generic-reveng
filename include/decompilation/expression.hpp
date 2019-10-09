#pragma once

#include <optional>

#include <z3++.h>

namespace dec
{
    class expression;
}

namespace std
{
    template<>
    struct equal_to<dec::expression>
    {
        bool operator()(dec::expression const& expression_1, dec::expression const& expression_2) const;
    };
    template<>
    struct hash<dec::expression>
    {
        std::size_t operator()(dec::expression const& expression) const;
    };
}

namespace dec
{
    class expression : z3::expr
    {
        friend std::equal_to<expression>;
        friend std::hash<expression>;

        explicit expression(z3::expr const& base);

    public:

        explicit expression(std::string const& variable);
        explicit expression(std::uint64_t value);

        using z3::expr::to_string;

        bool has_value() const;
        std::uint64_t value() const;

        expression mem() const;

        expression operator-() const;
        expression operator~() const;

        expression operator+(expression const& other) const;
        expression operator-(expression const& other) const;
        expression operator*(expression const& other) const;
        expression operator/(expression const& other) const;
        expression operator%(expression const& other) const;

        expression operator&(expression const& other) const;
        expression operator|(expression const& other) const;
        expression operator^(expression const& other) const;
    };
}
