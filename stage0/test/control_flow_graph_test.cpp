#include <catch2/catch.hpp>

#include <sstream>

#include "../source/control_flow_graph.hpp"

control_flow_graph create_cfg_x86_32(std::vector<uint8_t> const& code)
{
    return control_flow_graph(
        disassembler(CS_ARCH_X86, CS_MODE_32),
        [&code](uint64_t const address)
        {
            return std::basic_string_view<uint8_t>(&code.at(address), code.size() - address);
        },
        0);
}

std::string cfg_string(control_flow_graph const& cfg)
{
    std::ostringstream cfg_str;

    size_t index = 0;
    for (auto const& [block, successors] : cfg)
    {
        if (index > 0)
            cfg_str << std::endl << std::endl;

        cfg_str << std::dec << index << ':';

        for (auto const& instruction : block)
        {
            cfg_str << std::endl << std::hex << std::uppercase << instruction->address << ' '
                << std::begin(instruction->mnemonic);

            std::string const op_str = std::begin(instruction->op_str);
            if (!op_str.empty())
                cfg_str << ' ' << op_str;
        }

        if (!successors.empty())
        {
            cfg_str << std::endl << "->";

            std::set<size_t> successor_indices;
            for (auto const& successor : successors)
                successor_indices.insert(std::distance(cfg.begin(), cfg.find(successor)));

            for (auto const index : successor_indices)
                cfg_str << ' ' << std::dec << index;
        }

        ++index;
    }

    return cfg_str.str();
}

TEST_CASE("Block transitioning: Linear")
{
    control_flow_graph cfg1 = create_cfg_x86_32(
        {
            0x90, // nop
            0xC3, // ret
            0xCC  // int3
        });
    control_flow_graph cfg2 = create_cfg_x86_32(
        {
            0x90, // nop
            0xCC, // int3
            0xCC  // int3
        });
    control_flow_graph cfg3 = create_cfg_x86_32(
        {
            0x90,       // nop
            0xEB, 0x00, // jmp +1
            0x90,       // nop
            0xC3        // ret
        });
    control_flow_graph cfg4 = create_cfg_x86_32(
        {
            0x90,       // nop
            0x74, 0x00, // je +1
            0x90,       // nop
            0xC3        // ret
        });

    std::ostringstream expected1;
    expected1        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 ret";
    std::ostringstream expected2;
    expected2        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 int3";
    std::ostringstream expected3;
    expected3        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 jmp 3"
        << std::endl << "3 nop"
        << std::endl << "4 ret";
    std::ostringstream expected4;
    expected4        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 je 3"
        << std::endl << "3 nop"
        << std::endl << "4 ret";

    CHECK(::cfg_string(cfg1) == expected1.str());
    CHECK(::cfg_string(cfg2) == expected2.str());
    CHECK(::cfg_string(cfg3) == expected3.str());
    CHECK(::cfg_string(cfg4) == expected4.str());
}

TEST_CASE("Block transitioning: Relocation")
{
    control_flow_graph cfg = create_cfg_x86_32(
        {
            0x90,       // nop
            0xEB, 0x01, // jmp +2
            0xCC,       // int3
            0x90,       // nop
            0xC3        // ret
        });

    std::ostringstream expected;
    expected         << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 jmp 4"
        << std::endl << "-> 1"
        << std::endl
        << std::endl << "1:"
        << std::endl << "4 nop"
        << std::endl << "5 ret";

    CHECK(::cfg_string(cfg) == expected.str());
}

TEST_CASE("Block transitioning: IF-THEN-ELSE")
{
    control_flow_graph cfg = create_cfg_x86_32(
        {
            0x90,       // nop
            0x74, 0x03, // je +4
            0x90,       // nop
            0xC3,       // ret
            0xCC,       // int3
            0x90,       // nop
            0xC3        // ret
        });

    std::ostringstream expected;
    expected         << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 je 6"
        << std::endl << "-> 1 2"
        << std::endl
        << std::endl << "1:"
        << std::endl << "3 nop"
        << std::endl << "4 ret"
        << std::endl
        << std::endl << "2:"
        << std::endl << "6 nop"
        << std::endl << "7 ret";

    CHECK(::cfg_string(cfg) == expected.str());
}

TEST_CASE("Block transitioning: IF-THEN")
{
    control_flow_graph cfg = create_cfg_x86_32(
        {
            0x90,       // nop
            0x75, 0x01, // jne +2
            0x90,       // nop
            0x90,       // nop
            0xC3        // ret
        });

    std::ostringstream expected;
    expected         << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 jne 4"
        << std::endl << "-> 1 2"
        << std::endl
        << std::endl << "1:"
        << std::endl << "3 nop"
        << std::endl << "-> 2"
        << std::endl
        << std::endl << "2:"
        << std::endl << "4 nop"
        << std::endl << "5 ret";

    CHECK(::cfg_string(cfg) == expected.str());
}

TEST_CASE("Block transitioning: Diamond")
{
    control_flow_graph cfg1 = create_cfg_x86_32(
        {
            0x90,       // nop
            0x74, 0x04, // je +4
            0x90,       // nop
            0xEB, 0x02, // jmp +3
            0xCC,       // int3
            0x90,       // nop
            0x90,       // nop
            0xC3        // ret
        });
    control_flow_graph cfg2 = create_cfg_x86_32(
        {
            0x90,       // nop
            0x74, 0x04, // je +5
            0x90,       // nop
            0x90,       // nop
            0xC3,       // ret
            0xCC,       // int3
            0x90,       // nop
            0xEB, 0xFA  // jmp -4
        });

    std::ostringstream expected1;
    expected1        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 je 7"
        << std::endl << "-> 1 2"
        << std::endl
        << std::endl << "1:"
        << std::endl << "3 nop"
        << std::endl << "4 jmp 8"
        << std::endl << "-> 3"
        << std::endl
        << std::endl << "2:"
        << std::endl << "7 nop"
        << std::endl << "-> 3"
        << std::endl
        << std::endl << "3:"
        << std::endl << "8 nop"
        << std::endl << "9 ret";
    std::ostringstream expected2;
    expected2        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 je 7"
        << std::endl << "-> 1 3"
        << std::endl
        << std::endl << "1:"
        << std::endl << "3 nop"
        << std::endl << "-> 2"
        << std::endl
        << std::endl << "2:"
        << std::endl << "4 nop"
        << std::endl << "5 ret"
        << std::endl
        << std::endl << "3:"
        << std::endl << "7 nop"
        << std::endl << "8 jmp 4"
        << std::endl << "-> 2";

    CHECK(::cfg_string(cfg1) == expected1.str());
    CHECK(::cfg_string(cfg2) == expected2.str());
}

TEST_CASE("Block transitioning: Loop")
{
    control_flow_graph cfg1 = create_cfg_x86_32(
        {
            0x90,      // nop
            0xEB, 0xFD // jmp -1
        });
    control_flow_graph cfg2 = create_cfg_x86_32(
        {
            0x90,       // nop
            0x74, 0xFD, // je -1
            0x90,       // nop
            0xC3        // ret
        });
    control_flow_graph cfg3 = create_cfg_x86_32(
        {
            0x90,      // nop
            0x90,      // nop
            0xEB, 0xFD // jmp -1
        });
    control_flow_graph cfg4 = create_cfg_x86_32(
        {
            0x90,       // nop
            0x90,       // nop
            0x74, 0xFD, // je -1
            0x90,       // nop
            0xC3        // ret
        });

    std::ostringstream expected1;
    expected1        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 jmp 0"
        << std::endl << "-> 0";
    std::ostringstream expected2;
    expected2        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 je 0"
        << std::endl << "-> 0 1"
        << std::endl
        << std::endl << "1:"
        << std::endl << "3 nop"
        << std::endl << "4 ret";
    std::ostringstream expected3;
    expected3        << "0:"
        << std::endl << "0 nop"
        << std::endl << "-> 1"
        << std::endl
        << std::endl << "1:"
        << std::endl << "1 nop"
        << std::endl << "2 jmp 1"
        << std::endl << "-> 1";
    std::ostringstream expected4;
    expected4        << "0:"
        << std::endl << "0 nop"
        << std::endl << "-> 1"
        << std::endl
        << std::endl << "1:"
        << std::endl << "1 nop"
        << std::endl << "2 je 1"
        << std::endl << "-> 1 2"
        << std::endl
        << std::endl << "2:"
        << std::endl << "4 nop"
        << std::endl << "5 ret";

    CHECK(::cfg_string(cfg1) == expected1.str());
    CHECK(::cfg_string(cfg2) == expected2.str());
    CHECK(::cfg_string(cfg3) == expected3.str());
    CHECK(::cfg_string(cfg4) == expected4.str());
}
