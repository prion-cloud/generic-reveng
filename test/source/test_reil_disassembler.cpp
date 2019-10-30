#include <revengine/reil_disassembler.hpp>

#include "test.hpp"

TEST_CASE("rev::dis::reil_disassembler::operator(rev::data_section) const")
{
    auto const address = GENERATE(as<std::uint64_t>(), // NOLINT
        0, 1, 17, 1639);

    rev::machine_architecture architecture;
    std::vector<std::uint8_t> data;

    rev::machine_impact impact;

    SECTION("x86_32")
    {
        architecture = rev::machine_architecture::x86_32;

        SECTION("A")
        {
            SECTION("int3")
            {
                data = { 0xCC };
            }
            SECTION("ret")
            {
                data = { 0xC3 };

                impact[rev::expression::unknown("R_ESP")] = rev::expression::unknown("R_ESP") + rev::expression::value(4);
                impact.jump(rev::expression::unknown("R_ESP").mem());
            }
        }
        SECTION("B")
        {
            SECTION("nop")
            {
                data = { 0x90 };
            }
            SECTION("mov eax, [27]")
            {
                data = { 0xA1, 0x1B, 0x00, 0x00, 0x00 };

                impact[rev::expression::unknown("R_EAX")] = rev::expression::value(27).mem();
            }
            SECTION("mov [27], eax")
            {
                data = { 0xA3, 0x1B, 0x00, 0x00, 0x00 };

                impact[rev::expression::value(27).mem()] = rev::expression::unknown("R_EAX");
            }

            impact.jump(rev::expression::value(address + data.size()));
        }
    }
    // TODO x86_64, etc.

    rev::dis::reil_disassembler const reil_disassembler(architecture);
    rev::data_section data_section
    {
        .address = address,
        .data = std::basic_string_view(data.data(), data.size())
    };

    auto const actual_impact = reil_disassembler(&data_section);

    CHECK(data_section.address == address);
    CHECK(data_section.data.size() == data.size());

    assert_content<rev::expression>(impact.jump(), *reinterpret_cast<std::unordered_set<rev::expression> const*>(&actual_impact.jump()));
    CHECK(actual_impact == impact);
}
