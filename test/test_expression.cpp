#include "test.hpp"

constexpr std::equal_to<dec::expression> equal_to;

TEST_CASE("dec::expression::resolve(dec::expression, dec::expression)")
{
    std::unique_ptr<dec::expression> base_expression;

    std::unique_ptr<dec::expression const> a;
    std::unique_ptr<dec::expression const> b;

    std::unique_ptr<dec::expression const> result_expression;

    SECTION("A")
    {
        base_expression = std::make_unique<dec::expression>(GENERATE( // NOLINT
            dec::expression::value(0),
            dec::expression::unknown("TEST")));

        b = std::make_unique<dec::expression const>(GENERATE( // NOLINT
            dec::expression::value(0),
            dec::expression::value(1),
            dec::expression::value(2),
            dec::expression::unknown("TEST"),
            dec::expression::unknown("x"),
            dec::expression::unknown("x") == dec::expression::value(7)));

        SECTION("A1")
        {
            a = std::make_unique<dec::expression const>(GENERATE( // NOLINT
                dec::expression::value(1),
                dec::expression::unknown("NONE")));

            result_expression = std::make_unique<dec::expression const>(*base_expression);
        }
        SECTION("A2")
        {
            a = std::make_unique<dec::expression const>(*base_expression);

            result_expression = std::make_unique<dec::expression const>(*b);
        }
    }
    SECTION("B")
    {
        auto const unknown = GENERATE( // NOLINT
            dec::expression::unknown("TEST"),
            dec::expression::unknown("n"),
            dec::expression::unknown("25"));

        auto const addend_1 = GENERATE(as<std::uint64_t>(), // NOLINT
            0, 1, 2, 3, 4);
        auto const addend_2 = GENERATE(as<std::uint64_t>(), // NOLINT
            0, 1, 2, 3, 4);

        a = std::make_unique<dec::expression const>(unknown);
        b = std::make_unique<dec::expression const>(dec::expression::value(addend_1));

        SECTION("+")
        {
            base_expression = std::make_unique<dec::expression>(unknown + dec::expression::value(addend_2));
            result_expression = std::make_unique<dec::expression const>(dec::expression::value(addend_1 + addend_2));
        }
        SECTION("*")
        {
            base_expression = std::make_unique<dec::expression>(unknown * dec::expression::value(addend_2));
            result_expression = std::make_unique<dec::expression const>(dec::expression::value(addend_1 * addend_2));
        }
    }

    base_expression->resolve(*a, *b);

    CHECK(equal_to(*base_expression, *result_expression));
}

TEST_CASE("dec::expression::evaluate() const")
{
    std::unique_ptr<dec::expression const> expression;

    std::optional<std::uint64_t> value;

    SECTION("A")
    {
        value = GENERATE( // NOLINT
            0, 1, 2, 3, 4);

        expression = std::make_unique<dec::expression const>(dec::expression::value(*value));
    }
    SECTION("B")
    {
        auto const name = GENERATE(as<std::string>(), // NOLINT
            "TEST", "RAX", "rbx");
        expression = std::make_unique<dec::expression const>(dec::expression::unknown(name));

        value = std::nullopt;
    }

    CHECK(expression->evaluate() == value);
}

TEST_CASE("dec::expression::decompose() const")
{
    std::unique_ptr<dec::expression const> expression;

    std::vector<std::unique_ptr<dec::expression const>> components;

    SECTION("A")
    {
        expression = std::make_unique<dec::expression const>(dec::expression::value(0));
    }
    SECTION("B")
    {
        expression = std::make_unique<dec::expression const>(GENERATE( // NOLINT
            dec::expression::unknown("TEST"),
            dec::expression::unknown("EAX").mem()));

        components.push_back(std::make_unique<dec::expression const>(*expression));
    }
    SECTION("C")
    {
        expression = std::make_unique<dec::expression const>(
            dec::expression::unknown("EAX") * (dec::expression::unknown("EBX") + dec::expression::value(4)));

        components.push_back(std::make_unique<dec::expression const>(dec::expression::unknown("EAX")));
        components.push_back(std::make_unique<dec::expression const>(dec::expression::unknown("EBX")));
    }

    assert_content(components, expression->decompose(),
        [](auto const& a, auto const& b)
        {
            return equal_to(*a, b);
        });
}

TEST_CASE("dec::expression::operator==(expression) const")
{
    auto const expression = GENERATE( // NOLINT
        dec::expression::value(0),
        dec::expression::value(1),
        dec::expression::unknown("TEST"),
        dec::expression::unknown("TEST") + dec::expression::value(2));

    auto const a = expression;
    auto const b = expression;

    CHECK(equal_to(a, b));
}
TEST_CASE("dec::expression::operator!=(expression) const")
{
    std::unique_ptr<dec::expression const> a;
    std::unique_ptr<dec::expression const> b;

    SECTION("A")
    {
        a = std::make_unique<dec::expression const>(dec::expression::value(0));

        SECTION("A1")
        {
            b = std::make_unique<dec::expression const>(dec::expression::value(1));
        }
        SECTION("A2")
        {
            b = std::make_unique<dec::expression const>(dec::expression::unknown("TEST"));
        }
    }
    SECTION("B")
    {
        a = std::make_unique<dec::expression const>(dec::expression::unknown("TEST"));

        SECTION("B1")
        {
            b = std::make_unique<dec::expression const>(dec::expression::value(0));
        }
        SECTION("B2")
        {
            b = std::make_unique<dec::expression const>(dec::expression::value(1));
        }
    }

    CHECK(!equal_to(*a, *b));
}
