#include <utility>

#ifdef LINT
#include <generic-reveng/analysis/z3/z3_ast.hpp>
#endif

namespace grev
{
    template <typename Native>
    z3_ast<Native>::z3_ast(Native const& native) :
        native_(native)
    {
        increase_reference();
    }

    template <typename Native>
    z3_ast<Native>::~z3_ast()
    {
        decrease_reference();
    }

    template <typename Native>
    z3_ast<Native>::z3_ast(z3_ast const& other) :
        native_(other.native_)
    {
        increase_reference();
    }
    template <typename Native>
    z3_ast<Native>& z3_ast<Native>::operator=(z3_ast const& other)
    {
        if (&other != this)
        {
            decrease_reference();

            native_ = other.native_;

            increase_reference();
        }

        return *this;
    }

    template <typename Native>
    z3_ast<Native>::z3_ast(z3_ast&& other) noexcept :
        native_(std::exchange(other.native_, nullptr)) { }
    template <typename Native>
    z3_ast<Native>& z3_ast<Native>::operator=(z3_ast&& other) noexcept
    {
        if (&other != this)
        {
            decrease_reference();

            native_ = std::exchange(other.native_, nullptr);
        }

        return *this;
    }

    template <typename Native>
    z3_ast<Native>::operator std::conditional_t<is_native_ast, void, Native>() const
    {
        if constexpr (!is_native_ast)
            return native_;
    }

    template <typename Native>
    void z3_ast<Native>::increase_reference() const
    {
        Z3_inc_ref(context(), *this);
    }
    template <typename Native>
    void z3_ast<Native>::decrease_reference() const
    {
        Z3_dec_ref(context(), *this);
    }
}

#ifdef LINT
template class grev::z3_ast<Z3_ast>;
template class grev::z3_ast<Z3_func_decl>;
template class grev::z3_ast<Z3_sort>;
#endif
