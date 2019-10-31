#pragma once

#include <unordered_set>

#include <z3.h>

namespace rev
{
    class expression;
}

namespace std
{
    template<>
    struct equal_to<rev::expression>
    {
        bool operator()(rev::expression const& expression_1, rev::expression const& expression_2) const;
    };
    template<>
    struct hash<rev::expression>
    {
        std::size_t operator()(rev::expression const& expression) const;
    };
}

namespace rev
{
    class expression
    {
        static Z3_context context_;
        static Z3_sort sort_;

        static Z3_func_decl mem_;

        Z3_ast ast_;

        std::optional<std::uint64_t> value_;

        expression(Z3_ast const& ast);

    public:

        operator Z3_ast() const;
        operator bool() const;

        std::uint64_t operator*() const;

        void resolve(expression const& x, expression const& y);

        std::unordered_set<expression> decompose() const;

        expression mem() const;

        expression smul(expression const& other) const;
        expression sdiv(expression const& other) const;
        expression smod(expression const& other) const;

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

        static Z3_context const& context();

        static expression unknown(std::string const& name);
        static expression value(std::uint64_t value);

    private:

        static Z3_ast bool_value(Z3_ast const& ast);
    };
}
