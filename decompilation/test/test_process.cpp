#include <catch2/catch.hpp>

#include <decompilation/process.hpp>

struct instruction_info
{
    std::uint_fast64_t address;
    std::size_t size;

    std::vector<std::pair<std::string, std::string>> impact;

    static instruction_info make_int3(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 1,

            .impact = { }
        };
    }
    static instruction_info make_je(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 2,

            .impact = { }
        };
    }
    static instruction_info make_jmp(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 2,

            .impact = { }
        };
    }
    static instruction_info make_jmp_eax(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 2,

            .impact = { }
        };
    }
    static instruction_info make_jne(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 2,

            .impact = { }
        };
    }
    static instruction_info make_mov_eax_8(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 5,

            .impact =
            {
                { "R_EAX", "#x0000000000000008" }
            }
        };
    }
    static instruction_info make_mov_eax_mem27(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 5,

            .impact =
            {
                { "R_EAX", "(bvmem #x000000000000001b)" }
            }
        };
    }
    static instruction_info make_mov_mem28_ebx(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 6,

            .impact =
            {
                { "(bvmem #x000000000000001c)", "R_EBX" }
            }
        };
    }
    static instruction_info make_nop(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 1,

            .impact = { }
        };
    }
    static instruction_info make_ret(std::uint_fast64_t const address)
    {
        return
        {
            .address = address,
            .size = 1,

            .impact =
            {
                { "R_ESP", "(bvadd #x0000000000000004 R_ESP)" }
            }
        };
    }
};
struct process_info
{
    std::vector<std::uint_fast8_t> data;

    std::vector<std::vector<instruction_info>> blocks;
    std::vector<std::pair<std::uint_fast64_t, std::vector<std::uint_fast64_t>>> block_map;
};

template <typename ContainerExpected, typename ContainerActual, typename Compare>
void assert_content(ContainerExpected const& expected, ContainerActual actual, Compare const& compare)
{
    for (auto const& e : expected)
    {
        auto a = actual.begin();
        for (; a != actual.end(); ++a)
        {
            if (compare(e, *a))
                break;
        }

        REQUIRE(a != actual.end());

        actual.erase(a);
    }

    CHECK(actual.empty());
}

TEST_CASE("dec::process::process()")
{
    auto const expected = GENERATE( // NOLINT
        process_info
        {
            .data =
            {
                0xCC, // int3
                0xCC  // int3
            },
            .blocks =
            {
                { instruction_info::make_int3(0) }
            },
            .block_map =
            {
                { 0, { } }
            }
        },
        process_info
        {
            .data =
            {
                0xC3, // ret
                0xCC  // int3
            },
            .blocks =
            {
                { instruction_info::make_ret(0) }
            },
            .block_map =
            {
                { 0, { } }
            }
        },
        process_info
        {
            .data =
            {
                0x90, // nop
                0xC3  // ret
            },
            .blocks =
            {
                { instruction_info::make_nop(0), instruction_info::make_ret(1) }
            },
            .block_map =
            {
                { 0, { } }
            }
        },
        process_info
        {
            .data =
            {
                0xEB, 0x00, // jmp--,
                0xC3        // ret<-'
            },
            .blocks =
            {
                { instruction_info::make_jmp(0), instruction_info::make_ret(2) }
            },
            .block_map =
            {
                { 0, { } }
            }
        },
        process_info
        {
            .data =
            {
                0x74, 0x00, // je---,
                0xC3        // ret<-'
            },
            .blocks =
            {
                { instruction_info::make_je(0), instruction_info::make_ret(2) }
            },
            .block_map =
            {
                { 0, { } }
            }
        },
        process_info
        {
            .data =
            {
                0xEB, 0x01, // jmp--,
                0xCC,       // int3 |
                0xC3        // ret<-'
            },
            .blocks =
            {
                { instruction_info::make_jmp(0) },
                { instruction_info::make_ret(3) }
            },
            .block_map =
            {
                { 0, { 3 } },
                { 3, { } }
            }
        },
        process_info
        {
            .data =
            {
                0x75, 0x01, // jne--,  IF
                0x90,       // nop  |  THEN
                0xC3        // ret<-'
            },
            .blocks =
            {
                { instruction_info::make_jne(0) },
                { instruction_info::make_nop(2) },
                { instruction_info::make_ret(3) }
            },
            .block_map =
            {
                { 0, { 2, 3 } },
                { 2, { 3 } },
                { 3, { } }
            }
        },
        process_info
        {
            .data =
            {
                0x75, 0x01, // jne--,  IF
                0xC3,       // ret  |  THEN
                0xC3        // ret<-'  ELSE
            },
            .blocks =
            {
                { instruction_info::make_jne(0) },
                { instruction_info::make_ret(2) },
                { instruction_info::make_ret(3) }
            },
            .block_map =
            {
                { 0, { 2, 3 } },
                { 2, { } },
                { 3, { } }
            }
        },
        process_info
        {
            .data =
            {
                0x75, 0x03, // jne---, IF
                0xEB, 0x02, // jmp--,| THEN
                0xCC,       // int3 ||
                0x90,       // nop<-|' ELSE
                0xC3        // ret<-'
            },
            .blocks =
            {
                { instruction_info::make_jne(0) },
                { instruction_info::make_jmp(2) },
                { instruction_info::make_nop(5) },
                { instruction_info::make_ret(6) }
            },
            .block_map =
            {
                { 0, { 2, 5 } },
                { 2, { 6 } },
                { 5, { 6 } },
                { 6, { } }
            }
        },
        process_info
        {
            .data =
            {
                0x75, 0x03, // jne---, IF
                0x90,       // nop   | THEN
                0xC3,       // ret<-,|
                0xCC,       // int3 ||
                0xEB, 0xFC  // jmp<-'' ELSE
            },
            .blocks =
            {
                { instruction_info::make_jne(0) },
                { instruction_info::make_nop(2) },
                { instruction_info::make_ret(3) },
                { instruction_info::make_jmp(5) }
            },
            .block_map =
            {
                { 0, { 2, 5 } },
                { 2, { 3 } },
                { 3, { } },
                { 5, { 3 } }
            }
        },
        process_info
        {
            .data =
            {
                0xEB, 0xFE // jmp<-
            },
            .blocks =
            {
                { instruction_info::make_jmp(0) }
            },
            .block_map =
            {
                { 0, { 0 } }
            }
        },
        process_info
        {
            .data =
            {
                0x74, 0xFE, // je<-
                0xC3        // ret
            },
            .blocks =
            {
                { instruction_info::make_je(0) },
                { instruction_info::make_ret(2) }
            },
            .block_map =
            {
                { 0, { 0, 2 } },
                { 2, { } }
            }
        },
        process_info
        {
            .data =
            {
                0xB8, 0x08, 0x00, 0x00, 0x00, // mov eax, 8
                0xFF, 0xE0,                   // jmp eax
                0xCC,                         // int3
                0xC3                          // ret
            },
            .blocks =
            {
                { instruction_info::make_mov_eax_8(0), instruction_info::make_jmp_eax(5) },
//                { instruction_info::make_ret(8) }
            },
            .block_map =
            {
                { 0, { /*8*/ } },
//                { 8, { } }
            }
        },
        process_info
        {
            .data =
            {
                0xA1, 0x1B, 0x00, 0x00, 0x00,       // mov eax, [27]
                0x89, 0x1D, 0x1C, 0x00, 0x00, 0x00, // mov [28], ebx
                0xC3                                // ret
            },
            .blocks =
            {
                { instruction_info::make_mov_eax_mem27(0), instruction_info::make_mov_mem28_ebx(5), instruction_info::make_ret(11) },
            },
            .block_map =
            {
                { 0, { } },
            }
        });

    std::unique_ptr<dec::process> actual;
    REQUIRE_NOTHROW(actual = std::make_unique<dec::process>(expected.data, dec::instruction_set_architecture::x86_32));

    auto const expression_pair_compare =
        [](auto const& expected_expression_pair, auto const& actual_expression_pair)
        {
            return
                expected_expression_pair.first == actual_expression_pair.first.to_string() &&
                expected_expression_pair.second == actual_expression_pair.second.to_string();
        };

    SECTION("dec::process::blocks()")
    {
        auto const& actual_blocks = actual->blocks();
        REQUIRE(actual_blocks.size() == expected.blocks.size());

        auto block_index = 0;
        for (auto const& actual_block : actual_blocks)
        {
            auto const& expected_block = expected.blocks.at(block_index);
            REQUIRE(actual_block.size() == expected_block.size());

            auto instruction_index = 0;
            for (auto const& actual_instruction : actual_block)
            {
                auto const& expected_instruction = expected.blocks.at(block_index).at(instruction_index);

                CHECK(actual_instruction.address == expected_instruction.address);
                CHECK(actual_instruction.size == expected_instruction.size);

                assert_content(expected_instruction.impact, actual_instruction.impact, expression_pair_compare);

                ++instruction_index;
            }

            ++block_index;
        }
    }
    SECTION("dec::process::block_map()")
    {
        auto const& actual_block_map = actual->block_map();

        assert_content(expected.block_map, actual_block_map,
            [](auto const& expected_block_map_entry, auto const& actual_block_map_entry)
            {
                return expected_block_map_entry.first == actual_block_map_entry.first;
            });

        for (auto const& [expected_address, expected_succeeding_addresses] : expected.block_map)
            assert_content(expected_succeeding_addresses, actual_block_map.find(expected_address)->second, std::equal_to { });
    }
}
