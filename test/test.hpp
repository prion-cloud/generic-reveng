#pragma once

#include <algorithm>

template <typename SuperContainer, typename SubContainer>
bool includes(SuperContainer super_container, SubContainer const& sub_container)
{
    for (auto const& sub_element : sub_container)
    {
        auto const find_result = std::find_if(super_container.begin(), super_container.end(),
            [&sub_element](auto const& super_element)
            {
                return super_element == sub_element;
            });

        if (find_result == super_container.end())
            return false;

        super_container.erase(find_result);
    }

    return true;
}

template <typename Container1, typename Container2>
bool matches(Container1 const& container_1, Container2 const& container_2)
{
    return includes(container_1, container_2) && includes(container_2, container_1);
}
