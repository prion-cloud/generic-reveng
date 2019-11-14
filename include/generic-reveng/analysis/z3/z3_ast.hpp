#pragma once

#include <type_traits>

#include <generic-reveng/analysis/z3/z3_ast_base.hpp>

namespace grev
{
    template <typename Native>
    class z3_ast : public z3_ast_base
    {
        static constexpr bool is_native_ast = std::is_same_v<Native, Z3_ast>;

        Native native_;

    protected:

        explicit z3_ast(Native const& native);

    public:

        virtual ~z3_ast();

        z3_ast(z3_ast const& other);
        z3_ast& operator=(z3_ast const& other);

        z3_ast(z3_ast&& other) noexcept;
        z3_ast& operator=(z3_ast&& other) noexcept;

        operator std::conditional_t<is_native_ast, void, Native>() const; // NOLINT [hicpp-explicit-conversions]

        operator Z3_ast() const; // NOLINT [hicpp-explicit-conversions]

    private:

        void increase_reference() const;
        void decrease_reference() const;
    };
}

#ifndef LINT
#include <generic-reveng/analysis/z3/z3_ast.tpp>
#endif
