#pragma once

#include <functional>

#include <z3.h>

namespace rev::z3
{
    template <typename Base>
    class ast;
}

namespace std
{
    template <typename Base>
    struct equal_to<rev::z3::ast<Base>>
    {
        bool operator()(rev::z3::ast<Base> const& ast_1, rev::z3::ast<Base> const& ast_2) const;
    };
    template <typename Base>
    struct hash<rev::z3::ast<Base>>
    {
        std::size_t operator()(rev::z3::ast<Base> const& ast) const;
    };
}

namespace rev::z3
{
    template <typename Base>
    class ast
    {
        Base base_;

    protected:

        explicit ast(Base const& base);

    public:

        virtual ~ast();

        ast(ast const& other);
        ast& operator=(ast const& other);

        ast(ast&& other) noexcept;
        ast& operator=(ast&& other) noexcept;

        Base const& base() const; // TODO operator Base()

    private:

        void increase_reference() const;
        void decrease_reference() const;

        Z3_ast upcast() const;
    };
}

#ifndef LINT
#include <revengine/z3/template_ast.cpp>
#endif
