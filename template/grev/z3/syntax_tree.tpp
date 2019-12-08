#include <grev/z3/context.hpp>

#ifdef LINT
#include <grev/z3/syntax_tree.hpp>
#endif

namespace std
{
    template <typename Base>
    std::size_t hash<grev::z3::syntax_tree<Base>>::operator()(grev::z3::syntax_tree<Base> const& syntax_tree) const
    {
        return Z3_get_ast_hash(grev::z3::context(), static_cast<Z3_ast>(syntax_tree));
    }
}

namespace grev::z3
{
    template <typename Base>
    syntax_tree<Base>::syntax_tree(Base* const base) :
        base_(base)
    {
        Z3_inc_ref(context(), static_cast<Z3_ast>(*this));
    }

    template <typename Base>
    syntax_tree<Base>::~syntax_tree()
    {
        Z3_dec_ref(context(), static_cast<Z3_ast>(*this));
    }

    template <typename Base>
    syntax_tree<Base>::syntax_tree(syntax_tree const& other) :
        syntax_tree<Base>(other.base_) { }
    template <typename Base>
    syntax_tree<Base>::syntax_tree(syntax_tree&& other) noexcept :
        base_(std::exchange(other.base_, nullptr)) { }

    template <typename Base>
    syntax_tree<Base>& syntax_tree<Base>::operator=(syntax_tree other) noexcept
    {
        std::swap(base_, other.base_);

        return *this;
    }

    template <typename Base>
    Base* const& syntax_tree<Base>::base() const
    {
        return base_;
    }

    template <typename Base>
    bool syntax_tree<Base>::operator==(syntax_tree const& other) const
    {
        return Z3_is_eq_ast(context(), static_cast<Z3_ast>(*this), static_cast<Z3_ast>(other));
    }
    template <typename Base>
    bool syntax_tree<Base>::operator!=(syntax_tree const& other) const
    {
        return !(*this == other);
    }
}

#ifdef LINT
template class std::hash<grev::z3::syntax_tree<_Z3_ast>>;
template class grev::z3::syntax_tree<_Z3_ast>;
template class std::hash<grev::z3::syntax_tree<_Z3_func_decl>>;
template class grev::z3::syntax_tree<_Z3_func_decl>;
template class std::hash<grev::z3::syntax_tree<_Z3_sort>>;
template class grev::z3::syntax_tree<_Z3_sort>;
#endif
