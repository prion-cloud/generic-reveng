#pragma once

#include <algorithm>

template <typename SuperContainer, typename SubContainer, typename Equal>
bool includes(SuperContainer super_container, SubContainer const& sub_container, Equal const& equal)
{
    for (auto const& sub_element : sub_container)
    {
        auto const find_result = std::find_if(super_container.begin(), super_container.end(),
            [&equal, &sub_element](auto const& super_element)
            {
                return equal(super_element, sub_element);
            });

        if (find_result == super_container.end())
            return false;

        super_container.erase(find_result);
    }

    return true;
}
template <typename SuperContainer, typename SubContainer>
bool includes(SuperContainer const& super_container, SubContainer const& sub_container)
{
    static constexpr std::equal_to<std::remove_cvref_t<decltype(*super_container.begin())>> equal;
    return includes(super_container, sub_container, equal);
}
