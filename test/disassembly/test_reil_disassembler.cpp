#include <catch2/catch.hpp>

#include <generic-reveng/disassembly/reil_disassembler.hpp>

#include "test.hpp"

TEST_CASE("Disassembling", "[grev::reil_disassembler]")
{
    grev::machine_architecture architecture;

    auto const address = GENERATE(as<std::uint64_t>(),
        0, 1, 17, 1639);
    std::u8string data;

    grev::machine_state initial_state;

    std::unordered_map<grev::z3_expression, grev::z3_expression> expected_state;
    std::unordered_set<grev::z3_expression> expected_jumps;

    SECTION("x86_32")
    {
        architecture = grev::machine_architecture::x86_32;

        SECTION("A")
        {
            SECTION("int3")
            {
                data = { 0xCC };

                expected_jumps = std::unordered_set<grev::z3_expression> { };
            }
            SECTION("ret")
            {
                data = { 0xC3 };

                expected_state.emplace(grev::z3_expression("R_ESP"), grev::z3_expression("R_ESP") + grev::z3_expression(4));
                expected_jumps = { *grev::z3_expression("R_ESP") };
            }
        }
        SECTION("B")
        {
            SECTION("B1")
            {
                SECTION("nop")
                {
                    data = { 0x90 };
                }
                SECTION("mov eax, [27]")
                {
                    data = { 0xA1, 0x1B, 0x00, 0x00, 0x00 };

                    expected_state.emplace(grev::z3_expression("R_EAX"), *grev::z3_expression(27));
                }
                SECTION("mov [27], eax")
                {
                    data = { 0xA3, 0x1B, 0x00, 0x00, 0x00 };

                    expected_state.emplace(*grev::z3_expression(27), grev::z3_expression("R_EAX"));
                }
                SECTION("mov ebx, [eax]")
                {
                    data = { 0x8b, 0x18 };

                    expected_state.emplace(grev::z3_expression("R_EBX"), *grev::z3_expression("R_EAX"));
                }
                SECTION("mov [eax], ebx")
                {
                    data = { 0x89, 0x18 };

                    expected_state.emplace(*grev::z3_expression("R_EAX"), grev::z3_expression("R_EBX"));
                }
            }
            SECTION("B2")
            {
                initial_state.revise(grev::z3_expression("R_EAX"), grev::z3_expression(26));

                SECTION("mov eax, 27")
                {
                    data = { 0xb8, 0x1b, 0x00, 0x00, 0x00 };

                    expected_state.emplace(grev::z3_expression("R_EAX"), grev::z3_expression(27));
                }
            }

            expected_jumps = { grev::z3_expression(address + data.size()) };
        }
    }
    // TODO x86_64, etc.

    grev::reil_disassembler const reil_disassembler(architecture);

    grev::data_section data_section
    {
        .address = address,
        .data = data
    };
    auto const actual_update = reil_disassembler(&data_section);

    CHECK(data_section.address == address + data.size());
    CHECK(data_section.data.empty());

    grev::machine_state actual_state = std::move(initial_state);
    auto const actual_jumps = actual_update.resolve(&actual_state);

    CHECK(
        includes(
            *reinterpret_cast<std::unordered_map<grev::z3_expression, grev::z3_expression> const*>(&actual_state), // TODO
            expected_state,
            [](auto const& a, auto const& b)
            {
                static constexpr std::equal_to<grev::z3_expression> eq;
                return eq(a.first, b.first) && eq(a.second, b.second);
            }));

    CHECK(includes(expected_jumps, actual_jumps));
    CHECK(includes(actual_jumps, expected_jumps));
}
