#include <utility>

#ifdef LINT
#include <generic-reveng/analysis/z3/syntax_tree.hpp>
#endif

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
        native_(std::exchange(other.native_, nullptr)) { }

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
}

#ifdef LINT
template class grev::z3::syntax_tree<Z3_ast>;
template class grev::z3::syntax_tree<Z3_func_decl>;
template class grev::z3::syntax_tree<Z3_sort>;
#endif
