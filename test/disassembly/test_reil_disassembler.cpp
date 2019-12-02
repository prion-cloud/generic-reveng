#include <catch2/catch.hpp>

#include <generic-reveng/disassembly/reil_disassembler.hpp>

#include "test.hpp"

TEST_CASE("Disassembling", "[grev::reil_disassembler]")
{
    grev::machine_architecture architecture;

    auto const address = GENERATE(as<std::uint32_t>(),
        0, 1, 17, 1639);
    std::u8string data;

    grev::execution_state initial_state;

    std::unordered_map<grev::z3::expression, grev::z3::expression> expected_state;
    std::unordered_set<grev::z3::expression> expected_jumps;

    SECTION("x86_32")
    {
        architecture = grev::machine_architecture::x86_32;

        SECTION("A")
        {
            SECTION("ret")
            {
                data = { 0xC3 };

                expected_state.emplace(grev::z3::expression("R_ESP"), grev::z3::expression("R_ESP") + grev::z3::expression(4));
                expected_jumps = { grev::z3::expression("R_ESP").dereference() };
            }
        }
        SECTION("B")
        {
            SECTION("B1")
            {
                SECTION("int3")
                {
                    data = { 0xCC };
                }
                SECTION("nop")
                {
                    data = { 0x90 };
                }
                SECTION("mov eax, [27]")
                {
                    data = { 0xA1, 0x1B, 0x00, 0x00, 0x00 };

                    expected_state.emplace(grev::z3::expression("R_EAX"), grev::z3::expression(27).dereference());
                }
                SECTION("mov [27], eax")
                {
                    data = { 0xA3, 0x1B, 0x00, 0x00, 0x00 };

                    expected_state.emplace(grev::z3::expression(27).dereference(), grev::z3::expression("R_EAX"));
                }
                SECTION("mov ebx, [eax]")
                {
                    data = { 0x8b, 0x18 };

                    expected_state.emplace(grev::z3::expression("R_EBX"), grev::z3::expression("R_EAX").dereference());
                }
                SECTION("mov [eax], ebx")
                {
                    data = { 0x89, 0x18 };

                    expected_state.emplace(grev::z3::expression("R_EAX").dereference(), grev::z3::expression("R_EBX"));
                }
            }
            SECTION("B2")
            {
                initial_state.define(grev::z3::expression("R_EAX"), grev::z3::expression(26));

                SECTION("mov eax, 27")
                {
                    data = { 0xb8, 0x1b, 0x00, 0x00, 0x00 };

                    expected_state.emplace(grev::z3::expression("R_EAX"), grev::z3::expression(27));
                }
            }

            expected_jumps = { grev::z3::expression(address + data.size()) };
        }
    }
    // TODO x86_64, etc.

    grev::reil_disassembler const reil_disassembler(architecture);

    auto updated_address = address;
    std::u8string_view updated_data{data};

    auto const [update_state, actual_jumps] = reil_disassembler(&updated_address, &updated_data);

    CHECK(updated_address == address + data.size());
    CHECK(updated_data.empty());

    auto const actual_state = initial_state.resolve(update_state); // TODO Check only returned actual_state

    CHECK(
        includes(
            *reinterpret_cast<std::unordered_map<grev::z3::expression, grev::z3::expression> const*>(&actual_state), // TODO
            expected_state,
            [](auto const& a, auto const& b)
            {
                static constexpr std::equal_to<grev::z3::expression> eq;
                return eq(a.first, b.first) && eq(a.second, b.second);
            }));

    CHECK(includes(expected_jumps, actual_jumps));
    CHECK(includes(actual_jumps, expected_jumps));
}
