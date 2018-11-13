#include <catch2/catch.hpp>

#include <sstream>

#include "../include/scout/text_canvas.h"

#define TAG "[text_canvas]"

TEST_CASE("Drawing: One line, oversize", TAG)
{
    text_canvas tc(10);

    tc.draw("abcdefghijklmnopqrstuvwxyz", 0, 0);

    std::ostringstream expected;
    expected
        << "abcdefghij";

    CHECK(tc.str() == expected.str());
}

TEST_CASE("Drawing: Multiple lines, fitting, repositioned", TAG)
{
    text_canvas tc1(10), tc2(10), tc3(10), tc4(10);

    std::string const text = "abcdefghij\nklmnopqrst\nuvwxyz";

    tc1.draw(text, 0, 0);
    tc2.draw(text, 1, 0);
    tc3.draw(text, 0, 1);
    tc4.draw(text, 1, 1);

    std::ostringstream expected1;
    expected1        << "abcdefghij"
        << std::endl << "klmnopqrst"
        << std::endl << "uvwxyz    ";
    std::ostringstream expected2;
    expected2        << " abcdefghi"
        << std::endl << " klmnopqrs"
        << std::endl << " uvwxyz   ";
    std::ostringstream expected3;
    expected3        << "          "
        << std::endl << "abcdefghij"
        << std::endl << "klmnopqrst"
        << std::endl << "uvwxyz    ";
    std::ostringstream expected4;
    expected4        << "          "
        << std::endl << " abcdefghi"
        << std::endl << " klmnopqrs"
        << std::endl << " uvwxyz   ";

    CHECK(tc1.str() == expected1.str());
    CHECK(tc2.str() == expected2.str());
    CHECK(tc3.str() == expected3.str());
    CHECK(tc4.str() == expected4.str());
}

TEST_CASE("Drawing: Multi-byte string", TAG)
{
    text_canvas tc(5);

    tc.draw("\u2500 \u2500 \u2500 \u2500", 0, 0);

    std::ostringstream expected;
    expected
        << "\u2500 \u2500 \u2500";

    CHECK(tc.str() == expected.str());
}
