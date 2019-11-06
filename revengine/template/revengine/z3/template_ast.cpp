#include <utility>

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
        return Z3_get_base_hash(rev::z3::context::instance(), ast.base());
    }
}

namespace rev::z3
{
    template <typename Base>
    ast<Base>::ast(Base base) :
        base_(std::move(base))
    {
        Z3_inc_ref(context::instance(), reinterpret_cast<Z3_ast>(base_));
    }

    template <typename Base>
    ast<Base>::~ast()
    {
        Z3_dec_ref(context::instance(), reinterpret_cast<Z3_ast>(base_));
    }

    template <typename Base>
    ast<Base>::ast(ast const& other) :
        base_(other.base_)
    {
        Z3_inc_ref(context::instance(), reinterpret_cast<Z3_ast>(base_));
    }
    template <typename Base>
    ast<Base>& ast<Base>::operator=(ast const& other)
    {
        if (&other != this)
        {
            Z3_dec_ref(context::instance(), reinterpret_cast<Z3_ast>(base_));

            base_ = other.base_;

            Z3_inc_ref(context::instance(), reinterpret_cast<Z3_ast>(base_));
        }

        return *this;
    }

    template <typename Base>
    ast<Base>::ast(ast&& other) noexcept :
        base_(std::exchange(other.base_, { })) { }
    template <typename Base>
    ast<Base>& ast<Base>::operator=(ast&& other) noexcept
    {
        if (&other != this)
        {
            Z3_dec_ref(context::instance(), reinterpret_cast<Z3_ast>(base_));

            base_ = std::exchange(other.base_, { });
        }

        return *this;
    }

    template <typename Base>
    Base const& ast<Base>::base() const
    {
        return base_;
    }
}

#ifdef LINT
template class rev::z3::ast<Z3_ast>;
template class rev::z3::ast<Z3_func_decl>;
template class rev::z3::ast<Z3_sort>;
#endif
