#include "test.hpp"

constexpr std::equal_to<rev::expression> equal_to;

TEST_CASE("rev::expression::resolve(rev::expression, rev::expression)")
{
    std::unique_ptr<rev::expression> base_expression;

    std::unique_ptr<rev::expression const> a;
    std::unique_ptr<rev::expression const> b;

    std::unique_ptr<rev::expression const> result_expression;

    SECTION("A")
    {
        base_expression = std::make_unique<rev::expression>(GENERATE( // NOLINT
            rev::expression::value(0),
            rev::expression::unknown("TEST")));

        b = std::make_unique<rev::expression const>(GENERATE( // NOLINT
            rev::expression::value(0),
            rev::expression::value(1),
            rev::expression::value(2),
            rev::expression::unknown("TEST"),
            rev::expression::unknown("x"),
            rev::expression::unknown("x") == rev::expression::value(7)));

        SECTION("A1")
        {
            a = std::make_unique<rev::expression const>(GENERATE( // NOLINT
                rev::expression::value(1),
                rev::expression::unknown("NONE")));

            result_expression = std::make_unique<rev::expression const>(*base_expression);
        }
        SECTION("A2")
        {
            a = std::make_unique<rev::expression const>(*base_expression);

            result_expression = std::make_unique<rev::expression const>(*b);
        }
    }
    SECTION("B")
    {
        auto const unknown = GENERATE( // NOLINT
            rev::expression::unknown("TEST"),
            rev::expression::unknown("n"),
            rev::expression::unknown("25"));

        auto const addend_1 = GENERATE(as<std::uint64_t>(), // NOLINT
            0, 1, 2, 3, 4);
        auto const addend_2 = GENERATE(as<std::uint64_t>(), // NOLINT
            0, 1, 2, 3, 4);

        a = std::make_unique<rev::expression const>(unknown);
        b = std::make_unique<rev::expression const>(rev::expression::value(addend_1));

        SECTION("+")
        {
            base_expression = std::make_unique<rev::expression>(unknown + rev::expression::value(addend_2));
            result_expression = std::make_unique<rev::expression const>(rev::expression::value(addend_1 + addend_2));
        }
        SECTION("*")
        {
            base_expression = std::make_unique<rev::expression>(unknown * rev::expression::value(addend_2));
            result_expression = std::make_unique<rev::expression const>(rev::expression::value(addend_1 * addend_2));
        }
    }

    CHECK(equal_to(base_expression->resolve(*a, *b), *result_expression));
}

TEST_CASE("rev::expression::operator*() const")
{
    SECTION("A")
    {
        auto const value = GENERATE(as<std::uint64_t>(), // NOLINT
            0, 1, 2, 3, 4);

        auto const expression = rev::expression::value(value);

        CHECK(expression);
        CHECK(*expression == value);
    }
    SECTION("B")
    {
        auto const name = GENERATE(as<std::string>(), // NOLINT
            "TEST", "RAX", "rbx", "27");

        auto const expression = rev::expression::unknown(name);

        CHECK(!expression);
    }
}

TEST_CASE("rev::expression::decompose() const")
{
    std::unique_ptr<rev::expression const> expression;

    std::vector<std::unique_ptr<rev::expression const>> components;

    SECTION("A")
    {
        expression = std::make_unique<rev::expression const>(rev::expression::value(0));
    }
    SECTION("B")
    {
        expression = std::make_unique<rev::expression const>(GENERATE( // NOLINT
            rev::expression::unknown("TEST"),
            rev::expression::unknown("EAX").mem()));

        components.push_back(std::make_unique<rev::expression const>(*expression));
    }
    SECTION("C")
    {
        expression = std::make_unique<rev::expression const>(
            rev::expression::unknown("EAX") * (rev::expression::unknown("EBX") + rev::expression::value(4)));

        components.push_back(std::make_unique<rev::expression const>(rev::expression::unknown("EAX")));
        components.push_back(std::make_unique<rev::expression const>(rev::expression::unknown("EBX")));
    }

    assert_content(components, expression->decompose(),
        [](auto const& a, auto const& b)
        {
            return equal_to(*a, b);
        });
}

TEST_CASE("std::equal_to<rev::expression>::operator()(expression) const")
{
    auto const expression = GENERATE( // NOLINT
        rev::expression::value(0),
        rev::expression::value(1),
        rev::expression::unknown("TEST"),
        rev::expression::unknown("TEST") + rev::expression::value(2));

    auto const a = expression;
    auto const b = expression;

    CHECK(equal_to(a, b));
}
TEST_CASE("!std::equal_to<rev::expression>::operator()(expression) const")
{
    std::unique_ptr<rev::expression const> a;
    std::unique_ptr<rev::expression const> b;

    SECTION("A")
    {
        a = std::make_unique<rev::expression const>(rev::expression::value(0));

        SECTION("A1")
        {
            b = std::make_unique<rev::expression const>(rev::expression::value(1));
        }
        SECTION("A2")
        {
            b = std::make_unique<rev::expression const>(rev::expression::unknown("TEST"));
        }
    }
    SECTION("B")
    {
        a = std::make_unique<rev::expression const>(rev::expression::unknown("TEST"));

        SECTION("B1")
        {
            b = std::make_unique<rev::expression const>(rev::expression::value(0));
        }
        SECTION("B2")
        {
            b = std::make_unique<rev::expression const>(rev::expression::value(1));
        }
    }

    CHECK(!equal_to(*a, *b));
}
