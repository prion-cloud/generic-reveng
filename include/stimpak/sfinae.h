#pragma once

#include <type_traits>
#include <utility>

namespace stim
{
    namespace detail
    {
        template <typename T, typename TFunc>
        inline auto sfinae(TFunc&& func, T&& value, int)
            -> decltype(std::forward<TFunc>(func)(std::forward<T>(value)))
        {
            return std::forward<TFunc>(func)(std::forward<T>(value));
        }
        template <typename T, typename TFunc>
        inline T&& sfinae(TFunc&&, T&& value, long)
        {
            return std::forward<T>(value);
        }
    }

    template <typename T, typename TFunc>
    inline auto sfinae(TFunc&& func, T&& value)
    {
        return detail::sfinae(std::forward<TFunc>(func), std::forward<T>(value), 0);
    }
}
