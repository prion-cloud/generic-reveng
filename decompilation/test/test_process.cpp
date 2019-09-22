#include <catch2/catch.hpp>

#include <decompilation/process.hpp>

std::uint_fast8_t operator""_uf8(unsigned long long value) // NOLINT [google-runtime-int]
{
    return std::uint_fast8_t(value);
}
std::uint_fast64_t operator""_uf64(unsigned long long value) // NOLINT [google-runtime-int]
{
    return std::uint_fast64_t(value);
}

TEST_CASE("dec::process::process(dec::program)")
{
    auto const [data, expected_blocks, expected_block_map] = GENERATE( // NOLINT
        std::tuple
        {
            std::vector
            {
                0xCC_uf8, // int3
                0xCC_uf8  // int3
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector<std::uint_fast64_t> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0xC3_uf8, // ret
                0xCC_uf8  // int3
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector<std::uint_fast64_t> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x90_uf8, // nop
                0xC3_uf8  // ret
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64, 1_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector<std::uint_fast64_t> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0xEB_uf8, 0x00_uf8, // jmp--,
                0xC3_uf8            // ret<-'
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64, 2_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector<std::uint_fast64_t> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x74_uf8, 0x00_uf8, // je---,
                0xC3_uf8            // ret<-'
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64, 2_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector<std::uint_fast64_t> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0xEB_uf8, 0x01_uf8, // jmp--,
                0xCC_uf8,           // int3 |
                0xC3_uf8            // ret<-'
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 3_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 3_uf64 }              },
                std::pair { 3_uf64, std::vector<std::uint_fast64_t> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x75_uf8, 0x01_uf8, // jne--,  IF
                0x90_uf8,           // nop  |  THEN
                0xC3_uf8            // ret<-'
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 2_uf64 },
                std::vector { 3_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 2_uf64, 3_uf64 }      },
                std::pair { 2_uf64, std::vector { 3_uf64 }              },
                std::pair { 3_uf64, std::vector<std::uint_fast64_t> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x75_uf8, 0x01_uf8, // jne--,  IF
                0xC3_uf8,           // ret  |  THEN
                0xC3_uf8            // ret<-'  ELSE
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 2_uf64 },
                std::vector { 3_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 2_uf64, 3_uf64 }      },
                std::pair { 2_uf64, std::vector<std::uint_fast64_t> { } },
                std::pair { 3_uf64, std::vector<std::uint_fast64_t> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x75_uf8, 0x03_uf8, // jne---, IF
                0xEB_uf8, 0x02_uf8, // jmp--,| THEN
                0xCC_uf8,           // int3 ||
                0x90_uf8,           // nop<-|' ELSE
                0xC3_uf8            // ret<-'
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 2_uf64 },
                std::vector { 5_uf64 },
                std::vector { 6_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 2_uf64, 5_uf64 }      },
                std::pair { 2_uf64, std::vector { 6_uf64 }              },
                std::pair { 5_uf64, std::vector { 6_uf64 }              },
                std::pair { 6_uf64, std::vector<std::uint_fast64_t> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x75_uf8, 0x03_uf8, // jne---, IF
                0x90_uf8,           // nop   | THEN
                0xC3_uf8,           // ret<-,|
                0xCC_uf8,           // int3 ||
                0xEB_uf8, 0xFC_uf8  // jmp<-'' ELSE
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 2_uf64 },
                std::vector { 3_uf64 },
                std::vector { 5_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 2_uf64, 5_uf64 }      },
                std::pair { 2_uf64, std::vector { 3_uf64 }              },
                std::pair { 3_uf64, std::vector<std::uint_fast64_t> { } },
                std::pair { 5_uf64, std::vector { 3_uf64 }              }
            }
        },
        std::tuple
        {
            std::vector
            {
                0xEB_uf8, 0xFE_uf8 // jmp<-
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 0_uf64 } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x74_uf8, 0xFE_uf8, // je<-
                0xC3_uf8            // ret
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 2_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 0_uf64, 2_uf64 }      },
                std::pair { 2_uf64, std::vector<std::uint_fast64_t> { } }
            }
        });

    auto const actual = dec::process(data, dec::instruction_set_architecture::x86_32);

    SECTION("dec::process::blocks()")
    {
        REQUIRE(actual.blocks().size() == expected_blocks.size());

        auto block_index = 0;
        for (auto const& actual_block : actual.blocks())
        {
            auto instruction_index = 0;
            for (auto const& actual_instruction : actual_block)
            {
                CHECK(actual_instruction.address == expected_blocks.at(block_index).at(instruction_index));

                ++instruction_index;
            }

            ++block_index;
        }
    }
    SECTION("dec::process::block_map()")
    {
        auto actual_block_map = actual.block_map();

        for (auto const& [expected_address, expected_succeeding_addresses] : expected_block_map)
        {
            auto actual_block_map_entry = actual_block_map.begin();
            for (; actual_block_map_entry != actual_block_map.end(); ++actual_block_map_entry)
            {
                if (actual_block_map_entry->first == expected_address)
                    break;
            }

            REQUIRE(actual_block_map_entry != actual_block_map.end());

            auto actual_succeeding_addresses = actual_block_map_entry->second;
            actual_block_map.erase(actual_block_map_entry);

            for (auto const& expected_succeeding_address : expected_succeeding_addresses)
            {
                auto actual_succeeding_address = actual_succeeding_addresses.begin();
                for (; actual_succeeding_address != actual_succeeding_addresses.end(); ++actual_succeeding_address)
                {
                    if (*actual_succeeding_address == expected_succeeding_address)
                        break;
                }

                REQUIRE(actual_succeeding_address != actual_succeeding_addresses.end());

                actual_succeeding_addresses.erase(actual_succeeding_address);
            }

            CHECK(actual_succeeding_addresses.empty());
        }

        CHECK(actual_block_map.empty());
    }
}
