#pragma once

#include <unordered_set>

#include <generic-reveng/analysis/z3/syntax_tree.hpp>

namespace grev::z3
{
    class expression;
}

namespace std
{
    template <>
    struct hash<grev::z3::expression> : hash<grev::z3::syntax_tree<_Z3_ast>> { };
}

namespace grev::z3
{
    /*!
     *  Represents a mathematical expression relying on bit vectors.
     */
    class expression : public syntax_tree<_Z3_ast>
    {
        explicit expression(Z3_ast const& base);

    public:

        /*!
         *  Constructs a new variable of unspecified value.
         *  \param [in] name Distinctive name for representation
         */
        explicit expression(std::string const& name);
        /*!
         *  Constructs a new constant.
         *  \param [in] value Fixed integral value
         */
        explicit expression(std::uint32_t value);

        /*!
         *  Evaluates the expression to an integral value if possible.
         *  \returns Potential evaluation result
         */
        std::optional<std::uint32_t> evaluate() const;

        std::unordered_set<expression> dependencies() const;
        expression resolve_dependency(expression const& dependency, expression const& value) const;

        std::optional<expression> reference() const;
        expression dereference() const;

        expression equals(expression const&) const;
        expression less_than(expression const&) const;

        /*!
         *  Negation (two's complement)
         */
        expression operator-() const;
        /*!
         *  NOT (bitwise)
         */
        expression operator~() const;

        /*!
         *  Addition (two's complement)
         */
        expression& operator+=(expression const&);
        /*!
         *  Subtraction (two's complement)
         */
        expression& operator-=(expression const&);
        /*!
         *  Multiplication (unsigned)
         */
        expression& operator*=(expression const&);
        /*!
         *  Division (unsigned)
         */
        expression& operator/=(expression const&);
        /*!
         *  Remainder (unsigned)
         */
        expression& operator%=(expression const&);

        /*!
         *  AND (bitwise)
         */
        expression& operator&=(expression const&);
        /*!
         *  OR (bitwise)
         */
        expression& operator|=(expression const&);
        /*!
         *  XOR (bitwise)
         */
        expression& operator^=(expression const&);

        /*!
         *  Left shift (bitwise)
         */
        expression& operator<<=(expression const&);
        /*!
         *  Right shift (bitwise)
         */
        expression& operator>>=(expression const&);

    private:

        Z3_app application() const;

        bool dereferenced() const;

    public:

        static expression const& boolean_true();
        static expression const& boolean_false();

    private:

        static Z3_func_decl const& dereference_function();
    };

    /*!
     *  Addition (two's complement)
     */
    expression operator+(expression, expression const&);
    /*!
     *  Subtraction (two's complement)
     */
    expression operator-(expression, expression const&);
    /*!
     *  Multiplication (unsigned)
     */
    expression operator*(expression, expression const&);
    /*!
     *  Division (unsigned)
     */
    expression operator/(expression, expression const&);
    /*!
     *  Remainder (unsigned)
     */
    expression operator%(expression, expression const&);

    /*!
     *  AND (bitwise)
     */
    expression operator&(expression, expression const&);
    /*!
     *  OR (bitwise)
     */
    expression operator|(expression, expression const&);
    /*!
     *  XOR (bitwise)
     */
    expression operator^(expression, expression const&);

    /*!
     *  Left shift (bitwise)
     */
    expression operator<<(expression, expression const&);
    /*!
     *  Right shift (bitwise)
     */
    expression operator>>(expression, expression const&);
}
