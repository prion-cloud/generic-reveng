#include <decompilation/disassembler.hpp>

#include "test.hpp"

TEST_CASE("dec::disassembler::operator(dec::data_section) const")
{
    auto const address = GENERATE(as<std::uint64_t>(), // NOLINT
        0, 1, 17, 1639);

    dec::instruction_set_architecture architecture;
    std::vector<std::uint8_t> data;

    std::unordered_set<dec::expression> jump;
    dec::expression_composition impact;

    SECTION("x86_32")
    {
        architecture = dec::instruction_set_architecture::x86_32;

        SECTION("A")
        {
            SECTION("int3")
            {
                data = { 0xCC };
            }
            SECTION("ret")
            {
                data = { 0xC3 };

                jump.insert(dec::expression::unknown("R_ESP").mem());
                impact[dec::expression::unknown("R_ESP")] = dec::expression::unknown("R_ESP") + dec::expression::value(4);
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

                impact[dec::expression::unknown("R_EAX")] = dec::expression::value(27).mem();
            }
            SECTION("mov [27], eax")
            {
                data = { 0xA3, 0x1B, 0x00, 0x00, 0x00 };

                impact[dec::expression::value(27).mem()] = dec::expression::unknown("R_EAX");
            }

            jump.insert(dec::expression::value(address + data.size()));
        }
    }
    // TODO x86_64, etc.

    dec::instruction const expected_instruction
    {
        .address = address,
        .size = data.size(),

        .jump = jump,
        .impact = impact
    };

    dec::disassembler const disassembler(architecture);
    dec::data_section const data_section
    {
        .address = address,
        .data = std::basic_string_view(data.data(), data.size())
    };

    auto const actual_instruction = disassembler(data_section);

    CHECK(actual_instruction.address == expected_instruction.address);
    CHECK(actual_instruction.size == expected_instruction.size);

    assert_content<dec::expression>(expected_instruction.jump, actual_instruction.jump);
    CHECK(actual_instruction.impact == expected_instruction.impact);
}
