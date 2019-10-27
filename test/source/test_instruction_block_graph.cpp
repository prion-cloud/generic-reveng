#include <revengine/instruction_block_graph.hpp>
#include <revengine/disassembler.hpp>

#include "test.hpp"

#define ADD_EAX_EBX 0x01, 0xD8
#define ADD_EAX(v) 0x83, 0xC0, std::uint8_t(v)
#define INT3 0xCC
#define JE(v) 0x74, std::uint8_t(v)
#define JMP(v) 0xEB, std::uint8_t(v)
#define JMP_EAX 0xFF, 0xE0
#define JNE(v) 0x75, std::uint8_t(v)
#define MOV_EAX(v) 0xB8, std::uint8_t(v), 0x00, 0x00, 0x00
#define MOV_EBX(v) 0xBB, std::uint8_t(v), 0x00, 0x00, 0x00
#define NOP 0x90
#define RET 0xC3

TEST_CASE("rev::instruction_block_graph::instruction_block_graph(rev::process)")
{
    rev::instruction_set_architecture architecture;
    std::vector<std::uint8_t> data;

    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> expected_block_map;

    SECTION("x86_32")
    {
        architecture = rev::instruction_set_architecture::x86_32;

        SECTION("A")
        {
            data = GENERATE( // NOLINT
                std::vector<std::uint8_t>
                {
                    INT3,
                    INT3
                },
                std::vector<std::uint8_t>
                {
                    RET,
                    INT3
                },
                std::vector<std::uint8_t>
                {
                    NOP,
                    RET
                },
                std::vector<std::uint8_t>
                {
                    JMP(0), // --,
                    RET     // <-'
                },
                std::vector<std::uint8_t>
                {
                    JE(0), // --,
                    RET    // <-'
                });

            expected_block_map[0] = { };
        }
        SECTION("B")
        {
            data =
            {
                JMP(1), // --,
                INT3,   //   |
                RET     // <-'
            };

            expected_block_map[0] = { 3 };
            expected_block_map[3] = { };
        }
        SECTION("C")
        {
            data =
            {
                JNE(1), // --, IF
                NOP,    //   | THEN
                RET     // <-'
            };

            expected_block_map[0] = { 2, 3 };
            expected_block_map[2] = { 3 };
            expected_block_map[3] = { };
        }
        SECTION("D")
        {
            data =
            {
                JNE(1), // --, IF
                RET,    //   | THEN
                RET     // <-' ELSE
            };

            expected_block_map[0] = { 2, 3 };
            expected_block_map[2] = { };
            expected_block_map[3] = { };
        }
        SECTION("E")
        {
            data =
            {
                JNE(3), // ---, IF
                JMP(2), // --,| THEN
                INT3,   //   ||
                NOP,    // <-|' ELSE
                RET     // <-'
            };

            expected_block_map[0] = { 2, 5 };
            expected_block_map[2] = { 6 };
            expected_block_map[5] = { 6 };
            expected_block_map[6] = { };
        }
        SECTION("F")
        {
            data =
            {
                JNE(3), // ---, IF
                NOP,    //    | THEN
                RET,    // <-,|
                INT3,   //   ||
                JMP(-4) // <-'' ELSE
            };

            expected_block_map[0] = { 2, 5 };
            expected_block_map[2] = { 3 };
            expected_block_map[3] = { };
            expected_block_map[5] = { 3 };
        }
        SECTION("G")
        {
            data =
            {
                JMP(-2) // <- WHILE
            };

            expected_block_map[0] = { 0 };
        }
//        SECTION("H")
//        {
//            data =
//            {
//                JE(-2), // <- WHILE
//                RET
//            };
//
//            expected_block_map[0] = { 0, 2 };
//            expected_block_map[2] = { };
//        }
        SECTION("I")
        {
            data =
            {
                MOV_EAX(8),
                JMP_EAX, // --,
                INT3,    //   |
                RET      // <-'
            };

            expected_block_map[0] = { 8 };
            expected_block_map[8] = { };
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

            expected_block_map[0] = { 8 };
            expected_block_map[8] = { 11 };
            expected_block_map[11] = { };
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

            expected_block_map[0] = { 8 };
            expected_block_map[8] = { 16 };
            expected_block_map[16] = { 19 };
            expected_block_map[19] = { };
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

            expected_block_map[0] = { 8 };
            expected_block_map[8] = { 14 };
            expected_block_map[14] = { 17 };
            expected_block_map[17] = { };
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

            expected_block_map[0] = { 13 };
            expected_block_map[13] = { 18 };
            expected_block_map[18] = { };
        }
//        SECTION("N")
//        {
//            data =
//            {
//                JNE(8),      // ---, IF
//                MOV_EAX(18), //    | THEN
//                JMP(6),      // --,|
//                INT3,        //   ||
//                MOV_EAX(19), // <-|' ELSE
//                JMP_EAX,     // <-',
//                INT3,        //    |
//                RET,         // <--'
//                RET          // <--'
//            };
//
//            expected_block_map[0] = { 2, 10 };
//            expected_block_map[2] = { 15 };
//            expected_block_map[10] = { 15 };
//            expected_block_map[15] = { 18, 19 };
//            expected_block_map[18] = { };
//            expected_block_map[19] = { };
//        }
    }
    // TODO x86_64, etc.

    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> expected_block_map_reversed;
    for (auto const& [address, succeeding_addresses] : expected_block_map)
    {
        expected_block_map_reversed.try_emplace(address);

        for (auto const succeeding_address : succeeding_addresses)
            expected_block_map_reversed[succeeding_address].insert(address);
    }

    auto process = std::make_unique<rev::process const>(data, architecture);
    auto disassembler = std::make_unique<rev::dis::disassembler const>(process->architecture());

    auto instruction_block_graph = std::make_unique<rev::instruction_block_graph const>(*disassembler, *process);

    process.reset();
    disassembler.reset();

    auto const actual_block_map = instruction_block_graph->block_map();
    auto const actual_block_map_reversed = instruction_block_graph->block_map_reversed();

    instruction_block_graph.reset();

    CHECK(actual_block_map == expected_block_map);
    CHECK(actual_block_map_reversed == expected_block_map_reversed);
}
