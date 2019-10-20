#include "test.hpp"

TEST_CASE("dec::expression::substitute(dec::expression, dec::expression)")
{
    std::unique_ptr<dec::expression> base_expression;

    std::unique_ptr<dec::expression const> a;
    std::unique_ptr<dec::expression const> b;

    std::unique_ptr<dec::expression const> result_expression;

    SECTION("A")
    {
        base_expression = std::make_unique<dec::expression>(GENERATE(as<dec::expression>(), // NOLINT
            0, "TEST"));

        b = std::make_unique<dec::expression const>(GENERATE(as<dec::expression>(), // NOLINT
            0, 1, 2, "TEST", "x"));

        SECTION("A1")
        {
            a = std::make_unique<dec::expression const>(GENERATE(as<dec::expression>(), // NOLINT
                1, "NONE"));

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
        auto const unknown = GENERATE(as<dec::expression>(), // NOLINT
            "TEST", "n", "25");

        auto const addend_1 = GENERATE(as<std::uint64_t>(), // NOLINT
            0, 1, 2, 3, 4);
        auto const addend_2 = GENERATE(as<std::uint64_t>(), // NOLINT
            0, 1, 2, 3, 4);

        a = std::make_unique<dec::expression const>(unknown);
        b = std::make_unique<dec::expression const>(dec::expression(addend_1));

        SECTION("+")
        {
            base_expression = std::make_unique<dec::expression>(unknown + dec::expression(addend_2));
            result_expression = std::make_unique<dec::expression const>(addend_1 + addend_2);
        }
        SECTION("*")
        {
            base_expression = std::make_unique<dec::expression>(unknown * dec::expression(addend_2));
            result_expression = std::make_unique<dec::expression const>(addend_1 * addend_2);
        }
    }

    REQUIRE(base_expression->substitute(*a, *b) == *result_expression);
}

TEST_CASE("dec::expression::evaluate() const")
{
    std::unique_ptr<dec::expression const> expression;

    std::optional<std::uint64_t> value;

    SECTION("A")
    {
        value = GENERATE( // NOLINT
            0, 1, 2, 3, 4);

        expression = std::make_unique<dec::expression const>(*value);
    }
    SECTION("B")
    {
        auto const name = GENERATE( // NOLINT
            as<std::string>(),
            "TEST", "RAX", "rbx");
        expression = std::make_unique<dec::expression const>(name);

        value = std::nullopt;
    }

    REQUIRE(expression->evaluate() == value);
}

TEST_CASE("dec::expression::decompose() const")
{
    std::unique_ptr<dec::expression const> expression;

    std::vector<std::unique_ptr<dec::expression const>> components;

    SECTION("A")
    {
        expression = std::make_unique<dec::expression const>(0);
    }
    SECTION("B")
    {
        expression = std::make_unique<dec::expression const>(GENERATE(as<dec::expression>(), // NOLINT
            "TEST", dec::expression("EAX").mem()));

        components.push_back(std::make_unique<dec::expression const>(*expression));
    }
    SECTION("C")
    {
        expression = std::make_unique<dec::expression const>(
            dec::expression("EAX") * (dec::expression("EBX") + dec::expression(4)));

        components.push_back(std::make_unique<dec::expression const>("EAX"));
        components.push_back(std::make_unique<dec::expression const>("EBX"));
    }

    assert_content(components, expression->decompose(),
        [](auto const& a, auto const& b)
        {
            return *a == b;
        });
}

TEST_CASE("dec::expression::operator==(expression) const")
{
    std::unique_ptr<dec::expression const> expression;

    SECTION("A")
    {
        expression = std::make_unique<dec::expression const>(0);
    }
    SECTION("B")
    {
        expression = std::make_unique<dec::expression const>(1);
    }
    SECTION("C")
    {
        expression = std::make_unique<dec::expression const>("TEST");
    }

    auto const a = *expression;
    auto const b = *expression;

    expression.reset();

    CHECK(!(a != b));
    REQUIRE(a == b);
}
TEST_CASE("dec::expression::operator!=(expression) const")
{
    std::unique_ptr<dec::expression const> a;
    std::unique_ptr<dec::expression const> b;

    SECTION("A")
    {
        a = std::make_unique<dec::expression const>(0);

        SECTION("A1")
        {
            b = std::make_unique<dec::expression const>(1);
        }
        SECTION("A2")
        {
            b = std::make_unique<dec::expression const>("TEST");
        }
    }
    SECTION("B")
    {
        a = std::make_unique<dec::expression const>("TEST");

        SECTION("B1")
        {
            b = std::make_unique<dec::expression const>(0);
        }
        SECTION("B2")
        {
            b = std::make_unique<dec::expression const>(1);
        }
    }

    CHECK(!(*a == *b));
    REQUIRE(*a != *b);
}
