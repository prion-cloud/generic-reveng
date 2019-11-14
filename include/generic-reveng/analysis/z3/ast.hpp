#pragma once

#include <type_traits>

#include <generic-reveng/analysis/z3/ast_base.hpp>

namespace grev
{
    template <typename Native>
    class ast : public ast_base
    {
        static constexpr bool is_native_ast = std::is_same_v<Native, Z3_ast>;

        Native native_;

    protected:

        explicit ast(Native const& native);

    public:

        virtual ~ast();

        ast(ast const& other);
        ast& operator=(ast const& other);

        ast(ast&& other) noexcept;
        ast& operator=(ast&& other) noexcept;

        operator std::conditional_t<is_native_ast, void, Native>() const; // NOLINT [hicpp-explicit-conversions]

        operator Z3_ast() const; // NOLINT [hicpp-explicit-conversions]

    private:

        void increase_reference() const;
        void decrease_reference() const;
    };
}

#ifndef LINT
#include <generic-reveng/analysis/z3/ast.tpp>
#endif
