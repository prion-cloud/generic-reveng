#include <utility>

#ifdef LINT
#include <revengine/z3/ast.hpp>
#endif

namespace rev::z3
{
    template <typename Native>
    ast<Native>::ast(Native const& native) :
        native_(native)
    {
        increase_reference();
    }

    template <typename Native>
    ast<Native>::~ast()
    {
        decrease_reference();
    }

    template <typename Native>
    ast<Native>::ast(ast const& other) :
        native_(other.native_)
    {
        increase_reference();
    }
    template <typename Native>
    ast<Native>& ast<Native>::operator=(ast const& other)
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
    ast<Native>::ast(ast&& other) noexcept :
        native_(std::exchange(other.native_, nullptr)) { }
    template <typename Native>
    ast<Native>& ast<Native>::operator=(ast&& other) noexcept
    {
        if (&other != this)
        {
            decrease_reference();

            native_ = std::exchange(other.native_, nullptr);
        }

        return *this;
    }

    template <typename Native>
    ast<Native>::operator std::conditional_t<is_native_ast, void, Native>() const
    {
        if constexpr (!is_native_ast)
            return native_;
    }

    template <typename Native>
    void ast<Native>::increase_reference() const
    {
        Z3_inc_ref(context(), *this);
    }
    template <typename Native>
    void ast<Native>::decrease_reference() const
    {
        Z3_dec_ref(context(), *this);
    }
}

#ifdef LINT
template class rev::z3::ast<Z3_ast>;
template class rev::z3::ast<Z3_func_decl>;
template class rev::z3::ast<Z3_sort>;
#endif
