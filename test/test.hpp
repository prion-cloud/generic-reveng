#pragma once

#include <catch2/catch.hpp>

#include <decompilation/expression_block.hpp>

namespace Catch
{
    template<>
    struct StringMaker<dec::expression>
    {
        static std::string convert(dec::expression const& expression)
        {
            return expression.to_string();
        }
    };
    template<>
    struct StringMaker<dec::expression_block>
    {
        static std::string convert(dec::expression_block const& expression_block)
        {
            return StringMaker<std::vector<std::string>>::convert(expression_block.to_string());
        }
    };
}

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
template <typename ExpectedContainer, typename ActualContainer>
void assert_content(ExpectedContainer const& expected, ActualContainer const& actual)
{
    static std::equal_to const equal_to;
    assert_content(expected, actual, equal_to); // TODO Forwarding (?)
}
