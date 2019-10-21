#include "test.hpp"

TEST_CASE("dec::expression_composition::update(dec::expression_composition)")
{
    dec::expression_composition base_block;
    dec::expression_composition new_block;

    dec::expression_composition result_block;

    SECTION("A")
    {
        SECTION("A1")
        {
        }
        SECTION("A2")
        {
            new_block["EAX"] = dec::expression(1);

            result_block["EAX"] = dec::expression(1);
        }
    }
    SECTION("B")
    {
        base_block["EAX"] = dec::expression(1);

        SECTION("B1")
        {
            result_block["EAX"] = dec::expression(1);
        }
        SECTION("B2")
        {
            new_block["EAX"] = dec::expression(2);

            result_block["EAX"] = dec::expression(2);
        }
        SECTION("B3")
        {
            new_block["EAX"] = dec::expression("EAX") + dec::expression(2);

            result_block["EAX"] = dec::expression(3);
        }
        SECTION("B4")
        {
            new_block["EBX"] = dec::expression(2);

            result_block["EAX"] = dec::expression(1);
            result_block["EBX"] = dec::expression(2);
        }
        SECTION("B5")
        {
            new_block["EBX"] = dec::expression("EAX") + dec::expression(2);

            result_block["EAX"] = dec::expression(1);
            result_block["EBX"] = dec::expression(3);
        }
        SECTION("B6")
        {
            new_block["EAX"] = dec::expression("EBX") + dec::expression(3);
            new_block["EBX"] = dec::expression("EAX") + dec::expression(2);

            result_block["EAX"] = dec::expression("EBX") + dec::expression(3);
            result_block["EBX"] = dec::expression(3);
        }
    }
    SECTION("C")
    {
        base_block["EBX"] = dec::expression(1);

        SECTION("C1")
        {
            new_block["EAX"] = dec::expression("EBX") + dec::expression(2);
            new_block["EBX"] = dec::expression("EAX") + dec::expression(3);

            result_block["EAX"] = dec::expression(3);
            result_block["EBX"] = dec::expression("EAX") + dec::expression(3);
        }
    }

    CHECK(new_block.update(base_block) == result_block);
}

TEST_CASE("dec::expression_composition::operator==(dec::expression_composition) const")
{
    dec::expression_composition a;
    dec::expression_composition b;

    SECTION("A")
    {
        a["THIS"] = dec::expression(0);

        SECTION("A1")
        {
            b["THIS"] = dec::expression(0);
        }
        SECTION("A2")
        {
            b["THIS"] = dec::expression(0);
            b["OTHER"];
        }
        SECTION("A3")
        {
            b["THIS"] = dec::expression(0);
            b["OTHER"] = dec::expression("OTHER");
        }
    }
    SECTION("B")
    {
        a["THIS"] = dec::expression(0);
        a["OTHER"];

        SECTION("B1")
        {
            b["THIS"] = dec::expression(0);
        }
    }
    SECTION("C")
    {
        a["THIS"] = dec::expression(0);
        a["OTHER"] = dec::expression("OTHER");

        SECTION("C1")
        {
            b["THIS"] = dec::expression(0);
        }
    }
    SECTION("D")
    {
        a["THIS"] = dec::expression(0);
        a["OTHER"] = dec::expression(1);

        SECTION("D1: Same order")
        {
            b["THIS"] = dec::expression(0);
            b["OTHER"] = dec::expression(1);
        }
        SECTION("D2: Reversed order")
        {
            b["OTHER"] = dec::expression(1);
            b["THIS"] = dec::expression(0);
        }
    }

    CHECK(!(a != b));
    REQUIRE(a == b);
}
TEST_CASE("dec::expression_composition::operator!=(dec::expression_composition) const")
{
    dec::expression_composition a;
    dec::expression_composition b;

    SECTION("A")
    {
        a["THIS"] = dec::expression(0);

        SECTION("A1")
        {
            b["OTHER"] = dec::expression(0);
        }
        SECTION("A2")
        {
            b["THIS"] = dec::expression(1);
        }
    }

    CHECK(!(a == b));
    REQUIRE(a != b);
}
