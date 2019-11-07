#pragma once

#include <functional>

#include <z3.h>

#include <revengine/z3/ast_base.hpp>

namespace rev::z3
{
    template <typename Native>
    class ast;
}

namespace std
{
    template <typename Native>
    struct equal_to<rev::z3::ast<Native>>
    {
        bool operator()(rev::z3::ast<Native> const& ast_1, rev::z3::ast<Native> const& ast_2) const;
    };
    template <typename Native>
    struct hash<rev::z3::ast<Native>>
    {
        std::size_t operator()(rev::z3::ast<Native> const& ast) const;
    };
}

namespace rev::z3
{
    template <typename Native>
    class ast : public ast_base
    {
    public:

        using equal_to = std::equal_to<ast>;
        using hash = std::hash<ast>;

    private:

        Native native_;

    protected:

        explicit ast(Native const& native);

    public:

        virtual ~ast();

        ast(ast const& other);
        ast& operator=(ast const& other);

        ast(ast&& other) noexcept;
        ast& operator=(ast&& other) noexcept;

        operator Native() const;

        Z3_ast ast_native() const;

    private:

        void increase_reference() const;
        void decrease_reference() const;
    };
}

#ifndef LINT
#include <revengine/z3/ast.tpp>
#endif
