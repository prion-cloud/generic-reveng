#pragma once

#include <catch2/catch.hpp>

#include <decompilation/expression_composition.hpp>

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
    struct StringMaker<dec::expression_composition>
    {
        static std::string convert(dec::expression_composition const& expression_composition)
        {
            std::ostringstream ss;
            ss << '{';
            for (auto const& s : expression_composition.to_string())
                ss << std::endl << std::endl << std::endl << '\t' << s;
            ss << std::endl << '}';

            return ss.str();
        }
    };
    template<>
    struct StringMaker<std::pair<std::uint64_t const, std::unordered_set<std::uint64_t>>>
    {
        static std::string convert(std::pair<std::uint64_t const, std::unordered_set<std::uint64_t>> const& entry)
        {
            std::ostringstream ss;
            ss  << "{ "
                << entry.first << ", "
                << StringMaker<std::vector<std::uint64_t>>::convert(std::vector(entry.second.begin(), entry.second.end()))
                << " }";

            return ss.str();
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
