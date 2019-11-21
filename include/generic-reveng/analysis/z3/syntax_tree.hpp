#pragma once

#include <type_traits>

#include <generic-reveng/analysis/z3/syntax_tree_base.hpp>

namespace grev::z3
{
    template <typename Native>
    class syntax_tree : public syntax_tree_base
    {
        static constexpr bool is_native_ast = std::is_same_v<Native, Z3_ast>;

        Native native_;

    protected:

        explicit syntax_tree(Native native);

    public:

        virtual ~syntax_tree();

        syntax_tree(syntax_tree const& other);
        syntax_tree(syntax_tree&& other) noexcept;

        syntax_tree& operator=(syntax_tree other) noexcept;

        operator std::conditional_t<is_native_ast, void, Native>() const;

        operator Z3_ast() const;
    };
}

#ifndef LINT
#include <generic-reveng/analysis/z3/syntax_tree.tpp>
#endif
