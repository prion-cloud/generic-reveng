#include <catch2/catch.hpp>

#include <sstream>

#include "../include/scout/text_canvas.h"

#define TAG "[text_canvas]"

TEST_CASE("UTF-8 Drawing: One line, oversize", TAG)
{
    text_canvas tc(10);

    tc.print("abcdefghijklmnopqrstuvwxyz", 0, 0);

    CHECK(tc.str() == "abcdefghij");
}

TEST_CASE("UTF-8 Drawing: Multiple lines, fitting, repositioned", TAG)
{
    text_canvas tc1(10), tc2(10), tc3(10), tc4(10), tc5(10), tc6(10), tc7(10);

    std::string const text = "abcdefghij\nklmnopqrst\nuvwxyz";

    tc1.print(text,  0,  0);
    tc2.print(text,  1,  0);
    tc3.print(text,  0,  1);
    tc4.print(text,  1,  1);
    tc5.print(text, -1,  0);
    tc6.print(text,  0, -1);
    tc7.print(text, -1, -1);

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

    CHECK(tc1.str() == expected1.str());
    CHECK(tc2.str() == expected2.str());
    CHECK(tc3.str() == expected3.str());
    CHECK(tc4.str() == expected4.str());
    CHECK(tc5.str() == expected5.str());
    CHECK(tc6.str() == expected6.str());
    CHECK(tc7.str() == expected7.str());
}

TEST_CASE("UTF-8 Drawing: Multi-byte characters", TAG)
{
    text_canvas tc1(5), tc2(5);

    tc1.print("\u2500 \u2500 \u2500 \u2500",  0, 0);
    tc2.print("\u2500 \u2500 \u2500"       , -1, 0);

    CHECK(tc1.str() == "\u2500 \u2500 \u2500");
    CHECK(tc2.str() == " \u2500 \u2500 ");
}

TEST_CASE("UTF-8 Drawing: Centered", TAG)
{
    text_canvas tc1(10), tc2(10), tc3(10), tc4(10), tc5(10), tc6(10);

    std::string const text_even = "abcdef\nghijkl\nmnopq";
    std::string const text_odd = "abcde\nfghij\nklmn";

    tc1.print_centered(text_even,  0, 0);
    tc2.print_centered(text_even,  1, 0);
    tc3.print_centered(text_even, -1, 0);

    tc4.print_centered(text_odd,   0, 0);
    tc5.print_centered(text_odd,   1, 0);
    tc6.print_centered(text_odd,  -1, 0);

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

    CHECK(tc1.str() == expected1.str());
    CHECK(tc2.str() == expected2.str());
    CHECK(tc3.str() == expected3.str());
    CHECK(tc4.str() == expected4.str());
    CHECK(tc5.str() == expected5.str());
    CHECK(tc6.str() == expected6.str());
}
