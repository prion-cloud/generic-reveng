#pragma once

#include <unordered_set>

#include <z3++.h>

namespace dec
{
    class expression;
}

namespace std
{
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
        friend std::hash<expression>;

        static z3::func_decl mem_;

        explicit expression(z3::expr const& base);

    public:

        explicit expression(std::string const& name);
        explicit expression(std::uint64_t value);

        using z3::expr::to_string; // Debugging/testing purposes (TODO)

        void substitute(expression const& x, expression const& y);

        std::optional<std::uint64_t> evaluate() const;

        std::unordered_set<expression> decompose() const;

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

        // TODO missing operations

        bool operator==(expression const& other) const;
        bool operator!=(expression const& other) const;
    };
}
