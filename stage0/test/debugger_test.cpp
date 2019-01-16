#include <catch2/catch.hpp>

#include <sstream>

#include <libgen.h>

#include "../source/debugger.hpp"

std::string get_file_path(std::string const& file_name);

executable_specification create_executable(machine_architecture architecture, std::vector<uint8_t> code);

std::string cfg_string(control_flow_graph const& cfg);

TEST_CASE("Debug x86-32")
{
    auto d = debugger::load(::get_file_path("helloworld_32.exe"));

    CHECK(d->position() == 0x4012A8);

    /* TODO */
}
TEST_CASE("Debug x86-64")
{
    auto d = debugger::load(::get_file_path("helloworld_64.exe"));

    CHECK(d->position() == 0x140011023);

    /* TODO */
}

TEST_CASE("Block transitioning: Linear")
{
    debugger debugger1(
        create_executable(machine_architecture::x86_32,
        {
            0x90, // nop
            0xC3, // ret
            0xCC  // int3
        }));
    debugger debugger2(
        create_executable(machine_architecture::x86_32,
        {
            0x90, // nop
            0xCC, // int3
            0xCC  // int3
        }));
    debugger debugger3(
        create_executable(machine_architecture::x86_32,
        {
            0x90,       // nop
            0xEB, 0x00, // jmp +1
            0x90,       // nop
            0xC3        // ret
        }));
    debugger debugger4(
        create_executable(machine_architecture::x86_32,
        {
            0x90,       // nop
            0x74, 0x00, // je +1
            0x90,       // nop
            0xC3        // ret
        }));

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

    CHECK(::cfg_string(debugger1.cfg()) == expected1.str());
    CHECK(::cfg_string(debugger2.cfg()) == expected2.str());
    CHECK(::cfg_string(debugger3.cfg()) == expected3.str());
    CHECK(::cfg_string(debugger4.cfg()) == expected4.str());
}

TEST_CASE("Block transitioning: Relocation")
{
    debugger debugger(
        create_executable(machine_architecture::x86_32,
        {
            0x90,       // nop
            0xEB, 0x01, // jmp +2
            0xCC,       // int3
            0x90,       // nop
            0xC3        // ret
        }));

    std::ostringstream expected;
    expected         << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 jmp 4"
        << std::endl << "-> 1"
        << std::endl
        << std::endl << "1:"
        << std::endl << "4 nop"
        << std::endl << "5 ret";

    CHECK(::cfg_string(debugger.cfg()) == expected.str());
}

TEST_CASE("Block transitioning: IF-THEN-ELSE")
{
    debugger debugger(
        create_executable(machine_architecture::x86_32,
        {
            0x90,       // nop
            0x74, 0x03, // je +4
            0x90,       // nop
            0xC3,       // ret
            0xCC,       // int3
            0x90,       // nop
            0xC3        // ret
        }));

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

    CHECK(::cfg_string(debugger.cfg()) == expected.str());
}

TEST_CASE("Block transitioning: IF-THEN")
{
    debugger debugger(
        create_executable(machine_architecture::x86_32,
        {
            0x90,       // nop
            0x75, 0x01, // jne +2
            0x90,       // nop
            0x90,       // nop
            0xC3        // ret
        }));

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

    CHECK(::cfg_string(debugger.cfg()) == expected.str());
}

TEST_CASE("Block transitioning: Diamond")
{
    debugger debugger1(
        create_executable(machine_architecture::x86_32,
        {
            0x90,       // nop
            0x74, 0x04, // je +4
            0x90,       // nop
            0xEB, 0x02, // jmp +3
            0xCC,       // int3
            0x90,       // nop
            0x90,       // nop
            0xC3        // ret
        }));
    debugger debugger2(
        create_executable(machine_architecture::x86_32,
        {
            0x90,       // nop
            0x74, 0x04, // je +5
            0x90,       // nop
            0x90,       // nop
            0xC3,       // ret
            0xCC,       // int3
            0x90,       // nop
            0xEB, 0xFA  // jmp -4
        }));

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

    CHECK(::cfg_string(debugger1.cfg()) == expected1.str());
    CHECK(::cfg_string(debugger2.cfg()) == expected2.str());
}

TEST_CASE("Block transitioning: Loop")
{
    debugger debugger1(
        create_executable(machine_architecture::x86_32,
        {
            0x90,      // nop
            0xEB, 0xFD // jmp -1
        }));
    debugger debugger2(
        create_executable(machine_architecture::x86_32,
        {
            0x90,       // nop
            0x74, 0xFD, // je -1
            0x90,       // nop
            0xC3        // ret
        }));
    debugger debugger3(
        create_executable(machine_architecture::x86_32,
        {
            0x90,      // nop
            0x90,      // nop
            0xEB, 0xFD // jmp -1
        }));
    debugger debugger4(
        create_executable(machine_architecture::x86_32,
        {
            0x90,       // nop
            0x90,       // nop
            0x74, 0xFD, // je -1
            0x90,       // nop
            0xC3        // ret
        }));

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

    CHECK(::cfg_string(debugger1.cfg()) == expected1.str());
    CHECK(::cfg_string(debugger2.cfg()) == expected2.str());
    CHECK(::cfg_string(debugger3.cfg()) == expected3.str());
    CHECK(::cfg_string(debugger4.cfg()) == expected4.str());
}

std::string get_file_path(std::string const& file_name)
{
    return std::string(::dirname(std::string(__FILE__).data())) + "/" + file_name;
}

executable_specification create_executable(machine_architecture architecture, std::vector<uint8_t> code)
{
    return { architecture, 0, { { 0, code } } };
}

std::string cfg_string(control_flow_graph const& cfg)
{
    std::ostringstream cfg_ss;
    for (auto const& [block, successors] : cfg)
    {
        auto const block_node = cfg.find(block);

        auto const block_index = std::distance(cfg.begin(), block_node);

        if (block_index > 0)
            cfg_ss << std::endl << std::endl;

        cfg_ss << std::dec << block_index << ':';

        for (auto const& instruction : block)
        {
            cfg_ss << std::endl << std::hex << std::uppercase << instruction->address << ' '
                << std::begin(instruction->mnemonic);

            std::string const op_str = std::begin(instruction->op_str);
            if (!op_str.empty())
                cfg_ss << ' ' << op_str;
        }

        if (!successors.empty())
        {
            cfg_ss << std::endl << "->";

            std::set<size_t> successor_indices;
            for (auto const* successor : successors)
                successor_indices.insert(std::distance(cfg.begin(), cfg.find(*successor)));

            for (auto const index : successor_indices)
                cfg_ss << ' ' << std::dec << index;
        }
    }

    return cfg_ss.str();
}
