#pragma once

#include <memory>
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
    class expression
    {
        friend std::equal_to<expression>;
        friend std::hash<expression>;

        std::shared_ptr<z3::context> context_;
        z3::expr base_;
        z3::func_decl mem_;

        expression(std::shared_ptr<z3::context> context, z3::expr const& base);

    public:

        expression(std::shared_ptr<z3::context> const& context, std::string const& variable);
        expression(std::shared_ptr<z3::context> const& context, std::uint64_t value);

        std::string to_string() const;

        std::optional<std::uint64_t> evaluate() const;

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
