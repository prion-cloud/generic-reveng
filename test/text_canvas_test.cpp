#include <catch2/catch.hpp>

#include <iostream>

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
        << std::endl << "uvwxyz";
    std::ostringstream expected2;
    expected2        << " abcdefghi"
        << std::endl << " klmnopqrs"
        << std::endl << " uvwxyz";
    std::ostringstream expected3;
    expected3        << "          "
        << std::endl << "abcdefghij"
        << std::endl << "klmnopqrst"
        << std::endl << "uvwxyz";
    std::ostringstream expected4;
    expected4        << "          "
        << std::endl << " abcdefghi"
        << std::endl << " klmnopqrs"
        << std::endl << " uvwxyz";

    CHECK(tc1.str() == expected1.str());
    CHECK(tc2.str() == expected2.str());
    CHECK(tc3.str() == expected3.str());
    CHECK(tc4.str() == expected4.str());
}

TEST_CASE("Drawing: Multiple lines, overlapping", TAG)
{
    text_canvas tc(10);

    tc.draw("xxxxxxxxxx\nxxxxxxxxxx", 0, 0);
    tc.draw("abc    hij\nklm    rst", 0, 0);

    std::ostringstream expected;
    expected         << "abcxxxxhij"
        << std::endl << "klmxxxxrst";

    CHECK(tc.str() == expected.str());
}

TEST_CASE("Drawing: Trailing emptiness", TAG)
{
    text_canvas tc1(10), tc2(10), tc3(10), tc4(10);

    tc1.draw({ }, 0, 0);
    tc2.draw("    ", 0, 0);
    tc3.draw("abcdefg      ", 0, 0);
    tc4.draw("abcdefg\n    ", 0, 0);

    std::ostringstream expected3;
    expected3
        << "abcdefg";
    std::ostringstream expected4;
    expected4
        << "abcdefg";

    CHECK(tc1.str().empty());
    CHECK(tc2.str().empty());
    CHECK(tc3.str() == expected3.str());
    CHECK(tc4.str() == expected4.str());
}
