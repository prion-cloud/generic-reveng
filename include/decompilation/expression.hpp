#pragma once

#include <unordered_set>

#include <z3.h>

namespace dec
{
    class expression;
    class expression_composition;
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
    class expression // TODO : public std::optional<std::uint64_t>
    {
        friend std::hash<expression>;

        static Z3_context context_;
        static Z3_sort sort_;

        static Z3_func_decl mem_;

        Z3_ast ast_;

        explicit expression(Z3_ast const& ast);

    public:

        void resolve(expression const& x, expression const& y);
        void resolve(expression_composition const& c);

        std::string str() const; // Debugging/testing purposes (TODO)

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

        expression operator<<(expression const& other) const;
        expression operator>>(expression const& other) const;

        expression operator&(expression const& other) const;
        expression operator|(expression const& other) const;
        expression operator^(expression const& other) const;

        expression operator==(expression const& other) const;
        expression operator<(expression const& other) const;

        // TODO missing special UNsigned operations

        static expression unknown(std::string const& name);
        static expression value(std::uint64_t value);

    private:

        static Z3_ast bool_value(Z3_ast const& ast);
    };
}
