#include <catch2/catch.hpp>

#include <generic-reveng/analysis/machine_monitor.hpp>
#include <generic-reveng/disassembly/reil_disassembler.hpp> // TODO Mockup

#include "mock_program.hpp"
#include "test.hpp"

#define ADD_EAX_EBX 0x01, 0xD8
#define ADD_EAX(v) 0x83, 0xC0, char8_t(v)
#define INT3 0xCC
#define JE(v) 0x74, char8_t(v)
#define JMP(v) 0xEB, char8_t(v)
#define JMP_EAX 0xFF, 0xE0
#define JNE(v) 0x75, char8_t(v)
#define MOV_EAX(v) 0xB8, char8_t(v), 0x00, 0x00, 0x00
#define MOV_EBX(v) 0xBB, char8_t(v), 0x00, 0x00, 0x00
#define NOP 0x90
#define RET 0xC3

TEST_CASE("Path inspection", "[grev::machine_monitor]")
{
    grev::machine_architecture architecture;
    std::u8string data;

    std::vector<std::vector<std::uint64_t>> expected_path_addresses;

    SECTION("x86_32")
    {
        architecture = grev::machine_architecture::x86_32;

        SECTION("B")
        {
            data =
            {
                JMP(1), // --,
                INT3,   //   |
                RET     // <-'
            };

            expected_path_addresses =
            {
                { 0, 3 }
            };
        }
        SECTION("C")
        {
            data =
            {
                JNE(1), // --, IF
                NOP,    //   | THEN
                RET     // <-'
            };

            expected_path_addresses =
            {
                { 0, 2, 3 },
                { 0,    3 }
            };
        }
        SECTION("D")
        {
            data =
            {
                JNE(1), // --, IF
                RET,    //   | THEN
                RET     // <-' ELSE
            };

            expected_path_addresses =
            {
                { 0, 2 },
                { 0, 3 }
            };
        }
        SECTION("E")
        {
            data =
            {
                JNE(3), // ---, 0 IF
                JMP(2), // --,| 2 THEN
                INT3,   //   ||
                NOP,    // <-|' 5 ELSE
                RET     // <-'  6
            };

            expected_path_addresses =
            {
                { 0, 2, 6 },
                { 0, 5, 6 }
            };
        }
        SECTION("F")
        {
            data =
            {
                JNE(3), // ---, 0 IF
                NOP,    //    | 2 THEN
                RET,    // <-,| 3
                INT3,   //   ||
                JMP(-4) // <-'' 5 ELSE
            };

            expected_path_addresses =
            {
                { 0, 2, 3 },
                { 0, 5, 3 }
            };
        }
        SECTION("G")
        {
            data =
            {
                JMP(-2) // <- WHILE
            };

            expected_path_addresses =
            {
                { 0 }
            };
        }
        SECTION("H")
        {
            data =
            {
                JE(-2), // <- WHILE
                RET
            };

            expected_path_addresses =
            {
                { 0 },
                { 0, 2 }
            };
        }
        SECTION("I")
        {
            data =
            {
                MOV_EAX(8),
                JMP_EAX, // --,
                INT3,    //   |
                RET      // <-'
            };

            expected_path_addresses =
            {
                { 0, 5, 8 }
            };
        }
        SECTION("J")
        {
            data =
            {
                MOV_EAX(11),
                JMP(1),  // --,
                INT3,    //   |
                JMP_EAX, // <-',
                INT3,    //    |
                RET      // <--'
            };

            expected_path_addresses =
            {
                { 0, 5, 8, 11 }
            };
        }
        SECTION("K")
        {
            data =
            {
                MOV_EAX(18),
                JMP(1),      // --,
                INT3,        //   |
                MOV_EAX(19), // <-'
                JMP(1),      // --,
                INT3,        //   |
                JMP_EAX,     // <-',
                INT3,        //    |
                RET          // <--'
            };

            expected_path_addresses =
            {
                { 0, 5, 8, 13, 16, 19 }
            };
        }
        SECTION("L")
        {
            data =
            {
                MOV_EAX(8),
                JMP(1),     // --,
                INT3,       //   |
                ADD_EAX(9), // <-'
                JMP(1),     // --,
                INT3,       //   |
                JMP_EAX,    // <-',
                INT3,       //    |
                RET         // <--'
            };

            expected_path_addresses =
            {
                { 0, 5, 8, 11, 14, 17 }
            };
        }
        SECTION("M")
        {
            data =
            {
                MOV_EAX(12),
                MOV_EBX(6),
                JMP(1),      // --,
                INT3,        //   |
                ADD_EAX_EBX, // <-'
                JMP_EAX,     // --,
                INT3,        //   |
                RET          // <-'
            };

            expected_path_addresses =
            {
                { 0, 5, 10, 13, 15, 18 }
            };
        }
        SECTION("N")
        {
            data =
            {
                JNE(8),      // ---,  0 IF
                MOV_EAX(18), //    |  2 THEN
                JMP(6),      // --,|  7
                INT3,        //   ||
                MOV_EAX(19), // <-|' 10 ELSE
                JMP_EAX,     // <-', 15
                INT3,        //    |
                RET,         // <--' 18
                RET          // <--' 19
            };

            expected_path_addresses =
            {
                { 0,  2, 7, 15, 18 },
                { 0, 10,    15, 19 }
            };
        }
    }
    // TODO x86_64, etc.

    grev::reil_disassembler const disassembler(architecture);
    mock_program const program(data, architecture);

    grev::machine_monitor const machine_monitor(disassembler, program);

    assert_content(expected_path_addresses, machine_monitor.path_addresses(),
        [](auto const& expected_path, auto const& actual_path)
        {
            return expected_path == actual_path;
        });
}
