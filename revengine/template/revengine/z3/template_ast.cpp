#include <revengine/z3/context.hpp>

#ifdef LINT
#include <revengine/z3/ast.hpp>
#endif

namespace std // NOLINT [cert-dcl58-cpp]
{
    template <typename Base>
    bool equal_to<rev::z3::ast<Base>>::operator()(rev::z3::ast<Base> const& ast_1, rev::z3::ast<Base> const& ast_2) const
    {
        constexpr hash<rev::z3::ast<Base>> hash;
        return hash(ast_1) == hash(ast_2);
    }
    template <typename Base>
    std::size_t hash<rev::z3::ast<Base>>::operator()(rev::z3::ast<Base> const& ast) const
    {
        return Z3_get_ast_hash(rev::z3::context::instance(), ast.upcast());
    }
}

namespace rev::z3
{
    template <typename Base>
    ast<Base>::ast(Base const& base) :
        base_(base)
    {
        increase_reference();
    }

    template <typename Base>
    ast<Base>::~ast()
    {
        decrease_reference();
    }

    template <typename Base>
    ast<Base>::ast(ast const& other) :
        base_(other.base_)
    {
        increase_reference();
    }
    template <typename Base>
    ast<Base>& ast<Base>::operator=(ast const& other)
    {
        if (&other != this)
        {
            decrease_reference();

            base_ = other.base_;

            increase_reference();
        }

        return *this;
    }

    template <typename Base>
    ast<Base>::ast(ast&& other) noexcept :
        base_(std::exchange(other.base_, nullptr)) { }
    template <typename Base>
    ast<Base>& ast<Base>::operator=(ast&& other) noexcept
    {
        if (&other != this)
        {
            decrease_reference();

            base_ = std::exchange(other.base_, nullptr);
        }

        return *this;
    }

    template <typename Base>
    Base const& ast<Base>::base() const
    {
        return base_;
    }

    template <typename Base>
    void ast<Base>::increase_reference() const
    {
        Z3_inc_ref(context::instance(), upcast());
    }
    template <typename Base>
    void ast<Base>::decrease_reference() const
    {
        Z3_dec_ref(context::instance(), upcast());
    }
}

#ifdef LINT
template struct std::equal_to<rev::z3::ast<Z3_ast>>;
template struct std::equal_to<rev::z3::ast<Z3_func_decl>>;
template struct std::equal_to<rev::z3::ast<Z3_sort>>;
template struct std::hash<rev::z3::ast<Z3_ast>>;
template struct std::hash<rev::z3::ast<Z3_func_decl>>;
template struct std::hash<rev::z3::ast<Z3_sort>>;
template class rev::z3::ast<Z3_ast>;
template class rev::z3::ast<Z3_func_decl>;
template class rev::z3::ast<Z3_sort>;
#endif
