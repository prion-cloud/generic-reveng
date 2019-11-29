#pragma once

#include <functional>

#include <z3.h>

namespace grev::z3
{
    template <typename Base>
    class syntax_tree;
}

namespace std
{
    template <typename Base>
    struct hash<grev::z3::syntax_tree<Base>>
    {
        std::size_t operator()(grev::z3::syntax_tree<Base> const&) const;
    };
}

namespace grev::z3
{
    template <typename Base>
    class syntax_tree
    {
        Base* base_;

    protected:

        explicit syntax_tree(Base* base);

    public:

        explicit operator Z3_ast() const;

        virtual ~syntax_tree();

        syntax_tree(syntax_tree const&);
        syntax_tree(syntax_tree&&) noexcept;

        syntax_tree& operator=(syntax_tree) noexcept;

        Base* const& base() const;

        bool operator==(syntax_tree const&) const;
    };
}

#ifndef LINT
#include <generic-reveng/analysis/z3/syntax_tree.tpp>
#endif
