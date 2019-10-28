#pragma once

#include <sstream>

#include <catch2/catch.hpp>

#include <revengine/expression_composition.hpp>

namespace Catch
{
    template<>
    struct StringMaker<rev::expression>
    {
        static std::string convert(rev::expression const& expression)
        {
            return Z3_ast_to_string(rev::expression::context(), expression);
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
template <typename T, typename ExpectedContainer, typename ActualContainer>
void assert_content(ExpectedContainer const& expected, ActualContainer const& actual)
{
    constexpr std::equal_to<T> equal_to;
    assert_content(expected, actual, equal_to); // TODO Forwarding (?)
}
