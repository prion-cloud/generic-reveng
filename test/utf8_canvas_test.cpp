#include <catch2/catch.hpp>

#include <sstream>

#include "../include/scout/utf8_canvas.h"

#define TAG "[text_canvas]"

TEST_CASE("UTF-8 Drawing: One line, oversize", TAG)
{
    utf8_canvas c(10);

    c.print("abcdefghijklmnopqrstuvwxyz", 0, 0);

    CHECK(c.str() == "abcdefghij");
}

TEST_CASE("UTF-8 Drawing: Multiple lines, fitting, repositioned", TAG)
{
    utf8_canvas c1(10), c2(10), c3(10), c4(10), c5(10), c6(10), c7(10);

    std::vector<std::string> const text
    {
        "abcdefghij",
        "klmnopqrst",
        "uvwxyz"
    };

    c1.print(text,  0,  0);
    c2.print(text,  1,  0);
    c3.print(text,  0,  1);
    c4.print(text,  1,  1);
    c5.print(text, -1,  0);
    c6.print(text,  0, -1);
    c7.print(text, -1, -1);

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
    std::ostringstream expected5;
    expected5        << "bcdefghij "
        << std::endl << "lmnopqrst "
        << std::endl << "vwxyz     ";
    std::ostringstream expected6;
    expected6        << "klmnopqrst"
        << std::endl << "uvwxyz    ";
    std::ostringstream expected7;
    expected7        << "lmnopqrst "
        << std::endl << "vwxyz     ";

    CHECK(c1.str() == expected1.str());
    CHECK(c2.str() == expected2.str());
    CHECK(c3.str() == expected3.str());
    CHECK(c4.str() == expected4.str());
    CHECK(c5.str() == expected5.str());
    CHECK(c6.str() == expected6.str());
    CHECK(c7.str() == expected7.str());
}

TEST_CASE("UTF-8 Drawing: Multi-byte characters", TAG)
{
    utf8_canvas c1(5), c2(5);

    c1.print("\u2500 \u2500 \u2500 \u2500",  0, 0);
    c2.print("\u2500 \u2500 \u2500"       , -1, 0);

    CHECK(c1.str() == "\u2500 \u2500 \u2500");
    CHECK(c2.str() == " \u2500 \u2500 ");
}

TEST_CASE("UTF-8 Drawing: Centered", TAG)
{
    utf8_canvas c1(10), c2(10), c3(10), c4(10), c5(10), c6(10);

    std::vector<std::string> const text_even
    {
        "abcdef",
        "ghijkl",
        "mnopq"
    };
    std::vector<std::string> const text_odd
    {
        "abcde",
        "fghij",
        "klmn"
    };

    c1.print_centered(text_even,  0, 0);
    c2.print_centered(text_even,  1, 0);
    c3.print_centered(text_even, -1, 0);

    c4.print_centered(text_odd,   0, 0);
    c5.print_centered(text_odd,   1, 0);
    c6.print_centered(text_odd,  -1, 0);

    std::ostringstream expected1;
    expected1        << "  abcdef  "
        << std::endl << "  ghijkl  "
        << std::endl << "  mnopq   ";
    std::ostringstream expected2;
    expected2        << "   abcdef "
        << std::endl << "   ghijkl "
        << std::endl << "   mnopq  ";
    std::ostringstream expected3;
    expected3        << " abcdef   "
        << std::endl << " ghijkl   "
        << std::endl << " mnopq    ";

    std::ostringstream expected4;
    expected4        << "   abcde  "
        << std::endl << "   fghij  "
        << std::endl << "   klmn   ";
    std::ostringstream expected5;
    expected5        << "    abcde "
        << std::endl << "    fghij "
        << std::endl << "    klmn  ";
    std::ostringstream expected6;
    expected6        << "  abcde   "
        << std::endl << "  fghij   "
        << std::endl << "  klmn    ";

    CHECK(c1.str() == expected1.str());
    CHECK(c2.str() == expected2.str());
    CHECK(c3.str() == expected3.str());
    CHECK(c4.str() == expected4.str());
    CHECK(c5.str() == expected5.str());
    CHECK(c6.str() == expected6.str());
}
