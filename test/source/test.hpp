#pragma once

template <typename ExpectedContainer, typename ActualContainer, typename Compare>
void assert_content(ExpectedContainer const& expected, ActualContainer actual, Compare const& compare)
{
    // TODO Tidy up

    for (auto const& e : expected)
    {
        auto a = actual.begin();
        for (; a != actual.end(); ++a)
        {
            if (compare(e, *a))
                break;
        }

        CHECK(a != actual.end());

        if (a == actual.end())
            continue;

        actual.erase(a);
    }

    CHECK(actual.empty());
}
