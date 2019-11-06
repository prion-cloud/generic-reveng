#include <iomanip>

#include <catch2/catch.hpp>

#include <revengine/z3/expression.hpp>

#define TEST_NAMES "a"
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

//constexpr std::equal_to<rev::z3::expression> equal_to;

//std::string to_string(rev::z3::expression const& expression)
//{
//    return Z3_ast_to_string(rev::z3::expression::context(), expression.base());
//}
//std::string to_string(std::uint64_t const value)
//{
//    std::ostringstream stream;
//    stream << "#x" << std::setfill('0') << std::setw(sizeof(std::uint64_t) * 2) << std::hex << value;
//
//    return stream.str();
//}

TEST_CASE("Evaluate", "[rev::z3::expression]")
{
    SECTION("Unknown")
    {
        auto const name = GENERATE(as<std::string>(), TEST_NAMES); // NOLINT

        rev::z3::expression const a(name);

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
            SECTION("DEREF")
            {
                CHECK((*a).evaluate() == std::nullopt);
            }

            SECTION("NEG")
            {
                CHECK((-a).evaluate() == -value_a);
            }
            SECTION("NOT")
            {
                CHECK((~a).evaluate() == ~value_a);
            }
        }
        SECTION("Binary")
        {
            auto const value_b = GENERATE(as<std::uint64_t>(), TEST_VALUES); // NOLINT

            rev::z3::expression const b(value_b);

            SECTION("ADD")
            {
                CHECK((a + b).evaluate() == value_a + value_b);
            }
            SECTION("SUB")
            {
                CHECK((a - b).evaluate() == value_a - value_b);
            }

//            SECTION("MUL")
//            {
//                CHECK((a * b).evaluate() == value_a UMUL value_b);
//            }
//            SECTION("DIV")
//            {
//                CHECK((a / b).evaluate() == value_a UDIV value_b);
//            }
//            SECTION("MOD")
//            {
//                CHECK((a % b).evaluate() == value_a UMOD value_b);
//            }

//            SECTION("SMUL")
//            {
//                CHECK(a.smul(b).evaluate() == value_a SMUL value_b);
//            }
//            SECTION("SDIV")
//            {
//                CHECK(a.sdiv(b).evaluate() == value_a SDIV value_b);
//            }
//            SECTION("SMOD")
//            {
//                CHECK(a.smod(b).evaluate() == value_a SMOD value_b);
//            }

            SECTION("SHL")
            {
                CHECK((a << b).evaluate() == value_a << value_b);
            }
            SECTION("SHR")
            {
                CHECK((a >> b).evaluate() == value_a >> value_b);
            }

            SECTION("AND")
            {
                CHECK((a & b).evaluate() == (value_a & value_b));
            }
            SECTION("OR")
            {
                CHECK((a | b).evaluate() == (value_a | value_b));
            }
            SECTION("XOR")
            {
                CHECK((a ^ b).evaluate() == (value_a ^ value_b));
            }

            SECTION("EQ")
            {
                CHECK((a == b).evaluate() == (value_a == value_b ? 1 : 0));
            }
            SECTION("LT")
            {
                CHECK((a < b).evaluate() == (value_a < value_b ? 1 : 0));
            }
        }
    }
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
