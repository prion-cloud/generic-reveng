#include <utility>

#ifdef LINT
#include <generic-reveng/analysis/z3/syntax_tree.hpp>
#endif

namespace std // NOLINT [cert-dcl58-cpp]
{
    template <typename Native>
    bool equal_to<grev::z3::syntax_tree<Native>>::operator()(
        grev::z3::syntax_tree<Native> const& a,
        grev::z3::syntax_tree<Native> const& b) const
    {
        static constexpr std::hash<grev::z3::syntax_tree<Native>> hash;
        return hash(a) == hash(b);
    }
    template <typename Native>
    std::size_t hash<grev::z3::syntax_tree<Native>>::operator()(grev::z3::syntax_tree<Native> const& syntax_tree) const
    {
        return Z3_get_ast_hash(grev::z3::syntax_tree<Native>::context(), syntax_tree);
    }
}

namespace grev::z3
{
    template <typename Native>
    syntax_tree<Native>::syntax_tree(Native native) :
        native_(std::move(native))
    {
        Z3_inc_ref(context(), *this);
    }

    template <typename Native>
    syntax_tree<Native>::~syntax_tree()
    {
        Z3_dec_ref(context(), *this);
    }

    template <typename Native>
    syntax_tree<Native>::syntax_tree(syntax_tree const& other) :
        syntax_tree<Native>(other.native_) { }
    template <typename Native>
    syntax_tree<Native>::syntax_tree(syntax_tree&& other) noexcept :
        native_(std::exchange(other.native_, nullptr)) { } // TODO Generic move vs. z3 pointer semantics

    template <typename Native>
    syntax_tree<Native>& syntax_tree<Native>::operator=(syntax_tree other) noexcept
    {
        std::swap(native_, other.native_);

        return *this;
    }

    template <typename Native>
    syntax_tree<Native>::operator std::conditional_t<is_native_ast, void, Native>() const
    {
        if constexpr (!is_native_ast)
            return native_;
    }

    template <typename Native>
    bool syntax_tree<Native>::equals(syntax_tree const& other) const
    {
        static constexpr std::equal_to<syntax_tree<Native>> equal_to;
        return equal_to(*this, other);
    }
}

#ifdef LINT
template class grev::z3::syntax_tree<Z3_ast>;
template class grev::z3::syntax_tree<Z3_func_decl>;
template class grev::z3::syntax_tree<Z3_sort>;
#endif
