#include <catch2/catch.hpp>

#include <revengine/machine_monitor.hpp>
#include <revengine/reil_disassembler.hpp>

#include "revengine/mock_process.hpp"

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

TEST_CASE("Path inspection", "[rev::z3::machine_monitor]")
{
    rev::machine_architecture architecture;
    std::u8string data;

    std::vector<std::vector<std::uint64_t>> expected_paths;

    SECTION("x86_32")
    {
        architecture = rev::machine_architecture::x86_32;

        SECTION("B")
        {
            data =
            {
                JMP(1), // --,
                INT3,   //   |
                RET     // <-'
            };

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
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

            expected_paths =
            {
                { 0,  2, 7, 15, 18 },
                { 0, 10,    15, 19 }
            };
        }
    }
    // TODO x86_64, etc.

    mock_process const process(data, architecture);

    rev::machine_monitor<rev::dis::reil_disassembler> const machine_monitor(process); // TODO Disassembler mockup

    auto const& actual_paths = machine_monitor.paths();

    assert_content(expected_paths, std::vector(actual_paths.begin(), actual_paths.end()),
        [](auto const& expected_path, auto const& actual_path)
        {
            return expected_path == *reinterpret_cast<std::vector<std::uint64_t> const*>(&actual_path); // TODO
        });
}
