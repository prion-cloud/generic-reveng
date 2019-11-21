#include <utility>

#ifdef LINT
#include <generic-reveng/analysis/z3/z3_ast.hpp>
#endif

namespace grev
{
    template <typename Native>
    z3_ast<Native>::z3_ast(Native native) :
        native_(std::move(native))
    {
        Z3_inc_ref(context(), *this);
    }

    template <typename Native>
    z3_ast<Native>::~z3_ast()
    {
        Z3_dec_ref(context(), *this);
    }

    template <typename Native>
    z3_ast<Native>::z3_ast(z3_ast const& other) :
        z3_ast<Native>(other.native_) { }
    template <typename Native>
    z3_ast<Native>::z3_ast(z3_ast&& other) noexcept :
        native_(std::exchange(other.native_, nullptr)) { }

    template <typename Native>
    z3_ast<Native>& z3_ast<Native>::operator=(z3_ast other) noexcept
    {
        std::swap(native_, other.native_);

        return *this;
    }

    template <typename Native>
    z3_ast<Native>::operator std::conditional_t<is_native_ast, void, Native>() const
    {
        if constexpr (!is_native_ast)
            return native_;
    }
}

#ifdef LINT
template class grev::z3_ast<Z3_ast>;
template class grev::z3_ast<Z3_func_decl>;
template class grev::z3_ast<Z3_sort>;
#endif
