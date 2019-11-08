#include <catch2/catch.hpp>

#include <revengine/z3/expression.hpp>

#include "test.hpp"

#define TEST_NAMES "a", "0", "RAX"
#define TEST_VALUES 0, 0xA, 0x10

namespace Catch
{
    template<>
    struct StringMaker<std::optional<std::uint64_t>>
    {
        static std::string convert(std::optional<std::uint64_t> const& value)
        {
            if (value)
                return StringMaker<std::uint64_t>::convert(*value);

            return "(No value)";
        }
    };
}

TEST_CASE("Copy", "[rev::z3::expression]")
{
    auto const value = GENERATE(as<std::uint64_t>(), TEST_VALUES); // NOLINT

    auto a = std::make_unique<rev::z3::expression const>(value);

    SECTION("Construction")
    {
        rev::z3::expression const b = *a;

        CHECK(b.evaluate() == value);

        a.reset();

        CHECK(b.evaluate() == value);
    }
    SECTION("Assignment")
    {
        rev::z3::expression b(value + 1);
        b = *a;

        CHECK(b.evaluate() == value);

        a.reset();

        CHECK(b.evaluate() == value);
    }
}
TEST_CASE("Move", "[rev::z3::expression]")
{
    auto const value = GENERATE(as<std::uint64_t>(), TEST_VALUES); // NOLINT

    auto a = std::make_unique<rev::z3::expression>(value);

    SECTION("Construction")
    {
        rev::z3::expression const b = std::move(*a);

        CHECK(b.evaluate() == value);

        a.reset();

        CHECK(b.evaluate() == value);
    }
    SECTION("Assignment")
    {
        rev::z3::expression b(value + 1);
        b = std::move(*a);

        CHECK(b.evaluate() == value);

        a.reset();

        CHECK(b.evaluate() == value);
    }
}

TEST_CASE("Evaluate", "[rev::z3::expression]")
{
    SECTION("Unknown")
    {
        auto const name_a = GENERATE(as<std::string>(), TEST_NAMES); // NOLINT

        rev::z3::expression const a(name_a);

        CHECK(a.evaluate() == std::nullopt);
    }
    SECTION("Value")
    {
        auto const value_a = GENERATE(as<std::uint64_t>(), TEST_VALUES); // NOLINT

        rev::z3::expression const a(value_a);

        SECTION("Nullary")
        {
            CHECK(a.evaluate() == value_a);
        }
        SECTION("Unary")
        {
            SECTION("*") { CHECK((*a).evaluate() == std::nullopt); }

            SECTION("-") { CHECK((-a).evaluate() == -value_a); }
            SECTION("~") { CHECK((~a).evaluate() == ~value_a); }
        }
        SECTION("Binary")
        {
            auto const value_b = GENERATE(as<std::uint64_t>(), TEST_VALUES); // NOLINT

            rev::z3::expression const b(value_b);

            SECTION("+") { CHECK((a + b).evaluate() == value_a + value_b); }
            SECTION("-") { CHECK((a - b).evaluate() == value_a - value_b); }
//            SECTION("*") { CHECK((a * b).evaluate() == value_a UMUL value_b); }
//            SECTION("/") { CHECK((a / b).evaluate() == value_a UDIV value_b); }
//            SECTION("%") { CHECK((a % b).evaluate() == value_a UMOD value_b); }

//            SECTION("smul") { CHECK(a.smul(b).evaluate() == value_a SMUL value_b); }
//            SECTION("sdiv") { CHECK(a.sdiv(b).evaluate() == value_a SDIV value_b); }
//            SECTION("smod") { CHECK(a.smod(b).evaluate() == value_a SMOD value_b); }

            SECTION("<<") { CHECK((a << b).evaluate() == value_a << value_b); }
            SECTION(">>") { CHECK((a >> b).evaluate() == value_a >> value_b); }

            SECTION("&") { CHECK((a & b).evaluate() == (value_a & value_b)); }
            SECTION("|") { CHECK((a | b).evaluate() == (value_a | value_b)); }
            SECTION("^") { CHECK((a ^ b).evaluate() == (value_a ^ value_b)); }

            SECTION("==") { CHECK((a == b).evaluate() == (value_a == value_b ? 1 : 0)); }
            SECTION("<")  { CHECK((a <  b).evaluate() == (value_a <  value_b ? 1 : 0)); }
        }
    }
}

TEST_CASE("Decompose", "[rev::z3::expression]")
{
    static constexpr rev::z3::expression::equal_to eq;

    using e_set = std::unordered_set<rev::z3::expression, rev::z3::expression::hash, rev::z3::expression::equal_to>;

    SECTION("Value")
    {
        auto const value_a = GENERATE(as<std::uint64_t>(), TEST_VALUES); // NOLINT

        rev::z3::expression const a(value_a);

        assert_content(e_set { }, a.decompose(), eq);
    }
    SECTION("Unknown")
    {
        auto const name_a = GENERATE(as<std::string>(), TEST_NAMES); // NOLINT

        rev::z3::expression const a(name_a);

        SECTION("Nullary")
        {
            assert_content(e_set { a }, a.decompose(), eq);
        }
        SECTION("Unary")
        {
            SECTION("*") { assert_content(e_set { *a }, (*a).decompose(), eq); }

            SECTION("-") { assert_content(e_set { a }, (-a).decompose(), eq); }
            SECTION("~") { assert_content(e_set { a }, (~a).decompose(), eq); }
        }
        SECTION("Binary")
        {
            auto const name_b = GENERATE(as<std::string>(), TEST_NAMES); // NOLINT

            rev::z3::expression const b(name_b);

            SECTION("+") { assert_content(e_set { a, b }, (a + b).decompose(), eq); }
            SECTION("-") { assert_content(name_a == name_b ? e_set { } : e_set { a, b }, (a - b).decompose(), eq); }
//            SECTION("*") { assert_content(e_set { a, b }, (a * b).decompose(), eq); }
            SECTION("/") { assert_content(e_set { a, b }, (a / b).decompose(), eq); }
//            SECTION("%") { assert_content(e_set { a, b }, (a % b).decompose(), eq); }

            SECTION("smul") { assert_content(e_set { a, b }, a.smul(b).decompose(), eq); }
            SECTION("sdiv") { assert_content(e_set { a, b }, a.sdiv(b).decompose(), eq); }
            SECTION("smod") { assert_content(e_set { a, b }, a.smod(b).decompose(), eq); }

            SECTION("<<") { assert_content(e_set { a, b }, (a << b).decompose(), eq); }
            SECTION(">>") { assert_content(e_set { a, b }, (a >> b).decompose(), eq); }

            SECTION("&") { assert_content(e_set { a, b }, (a & b).decompose(), eq); }
            SECTION("|") { assert_content(e_set { a, b }, (a | b).decompose(), eq); }
            SECTION("^") { assert_content(name_a == name_b ? e_set { } : e_set { a, b }, (a ^ b).decompose(), eq); }

            SECTION("==") { assert_content(name_a == name_b ? e_set { } : e_set { a, b }, (a == b).decompose(), eq); }
            SECTION("<")  { assert_content(name_a == name_b ? e_set { } : e_set { a, b }, (a <  b).decompose(), eq); }
        }
    }
}

TEST_CASE("Resolve", "[rev::z3::expression]")
{
    static constexpr rev::z3::expression::equal_to eq;

    SECTION("Value")
    {
        rev::z3::expression const a(GENERATE(as<std::uint64_t>(), TEST_VALUES)); // NOLINT
        SECTION("A")
        {
            rev::z3::expression const x(GENERATE(as<std::string>(), TEST_NAMES)); // NOLINT
            SECTION("A1")
            {
                rev::z3::expression const y(GENERATE(as<std::string>(), TEST_NAMES)); // NOLINT
                CHECK(eq(a.resolve(x, y), a));
            }
            SECTION("A2")
            {
                rev::z3::expression const y(GENERATE(as<std::uint64_t>(), TEST_VALUES)); // NOLINT
                CHECK(eq(a.resolve(x, y), a));
            }
        }
        SECTION("B")
        {
            rev::z3::expression const x(GENERATE(as<std::uint64_t>(), TEST_VALUES)); // NOLINT
            SECTION("B1")
            {
                rev::z3::expression const y(GENERATE(as<std::string>(), TEST_NAMES)); // NOLINT
                CHECK(eq(a.resolve(x, y), eq(x, a) ? y : a));
            }
            SECTION("B2")
            {
                rev::z3::expression const y(GENERATE(as<std::uint64_t>(), TEST_VALUES)); // NOLINT
                CHECK(eq(a.resolve(x, y), eq(x, a) ? y : a));
            }
        }
    }
    SECTION("Unknown")
    {
        rev::z3::expression const a(GENERATE(as<std::string>(), TEST_NAMES)); // NOLINT
        SECTION("A")
        {
            rev::z3::expression const x(GENERATE(as<std::string>(), TEST_NAMES)); // NOLINT
            SECTION("A1")
            {
                rev::z3::expression const y(GENERATE(as<std::string>(), TEST_NAMES)); // NOLINT
                CHECK(eq(a.resolve(x, y), eq(x, a) ? y : a));
            }
            SECTION("A2")
            {
                rev::z3::expression const y(GENERATE(as<std::uint64_t>(), TEST_VALUES)); // NOLINT
                CHECK(eq(a.resolve(x, y), eq(x, a) ? y : a));
            }
        }
        SECTION("B")
        {
            rev::z3::expression const x(GENERATE(as<std::uint64_t>(), TEST_VALUES)); // NOLINT
            SECTION("B1")
            {
                rev::z3::expression const y(GENERATE(as<std::string>(), TEST_NAMES)); // NOLINT
                CHECK(eq(a.resolve(x, y), a));
            }
            SECTION("B2")
            {
                rev::z3::expression const y(GENERATE(as<std::uint64_t>(), TEST_VALUES)); // NOLINT
                CHECK(eq(a.resolve(x, y), a));
            }
        }
    }
}
