#pragma once

#include "sfinae.h"

namespace stim
{
    struct wrap_comparator
    {
        using is_transparent = std::true_type;

        template <typename T1, typename T2>
        inline bool operator()(T1&& value1, T2&& value2) const
        {
            auto const indirection =
                [](auto&& value)
                    -> decltype(*std::forward<decltype(value)>(value))
                {
                    return *std::forward<decltype(value)>(value);
                };

            return
                sfinae(indirection, std::forward<T1>(value1)) <
                sfinae(indirection, std::forward<T2>(value2));
        }
    };
}
