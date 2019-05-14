#include <catch2/catch.hpp>

#define private public // NOLINT [cppcoreguidelines-macro-usage]
#include <decompilation/process.hpp>
#undef private

auto const n_opt_uf64 = std::optional<std::uint_fast64_t>(std::nullopt);

std::byte operator""_b(unsigned long long value) // NOLINT [google-runtime-int]
{
    return std::byte(value);
}
std::uint_fast64_t operator""_uf64(unsigned long long value) // NOLINT [google-runtime-int]
{
    return std::uint_fast64_t(value);
}
std::optional<std::uint_fast64_t> operator""_opt_uf64(unsigned long long value) // NOLINT [google-runtime-int]
{
    return std::optional<std::uint_fast64_t>(value);
}

TEST_CASE("dec::process::process(dec::program)")
{
    auto const [data, expected_blocks, expected_block_map] = GENERATE( // NOLINT
        std::tuple
        {
            std::vector
            {
                0xCC_b,         // int3
                0xCC_b          // int3
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector<std::optional<std::uint_fast64_t>> { } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0xC3_b,         // ret
                0xCC_b          // int3
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { n_opt_uf64 } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x90_b,         // nop
                0xC3_b          // ret
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64, 1_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { n_opt_uf64 } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0xEB_b, 0x00_b, // jmp---,
                0xC3_b          // ret <-'
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64, 2_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { n_opt_uf64 } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x74_b, 0x00_b, // je----,
                0xC3_b          // ret <-'
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64, 2_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { n_opt_uf64 } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0xEB_b, 0x01_b, // jmp---,
                0xCC_b,         // int3  |
                0xC3_b          // ret <-'
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 3_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 3_opt_uf64 } },
                std::pair { 3_uf64, std::vector { n_opt_uf64 } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x75_b, 0x01_b, // jne---,  IF
                0x90_b,         // nop   |  THEN
                0xC3_b          // ret <-'
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 2_uf64 },
                std::vector { 3_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 2_opt_uf64, 3_opt_uf64 } },
                std::pair { 2_uf64, std::vector { 3_opt_uf64 }             },
                std::pair { 3_uf64, std::vector { n_opt_uf64 }             }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x75_b, 0x01_b, // jne---,  IF
                0xC3_b,         // ret   |  THEN
                0xC3_b          // ret <-'  ELSE
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 2_uf64 },
                std::vector { 3_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 2_opt_uf64, 3_opt_uf64 } },
                std::pair { 2_uf64, std::vector { n_opt_uf64 }             },
                std::pair { 3_uf64, std::vector { n_opt_uf64 }             }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x75_b, 0x03_b, // jne----, IF
                0xEB_b, 0x02_b, // jmp---,| THEN
                0xCC_b,         // int3  ||
                0x90_b,         // nop <-|' ELSE
                0xC3_b          // ret <-'
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
                std::pair { 0_uf64, std::vector { 2_opt_uf64, 5_opt_uf64 } },
                std::pair { 2_uf64, std::vector { 6_opt_uf64 }             },
                std::pair { 5_uf64, std::vector { 6_opt_uf64 }             },
                std::pair { 6_uf64, std::vector { n_opt_uf64 }             }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x75_b, 0x03_b, // jne----, IF
                0x90_b,         // nop    | THEN
                0xC3_b,         // ret <-,|
                0xCC_b,         // int3  ||
                0xEB_b, 0xFC_b  // jmp-<-'' ELSE
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
                std::pair { 0_uf64, std::vector { 2_opt_uf64, 5_opt_uf64 } },
                std::pair { 2_uf64, std::vector { 3_opt_uf64 }             },
                std::pair { 3_uf64, std::vector { n_opt_uf64 }             },
                std::pair { 5_uf64, std::vector { 3_opt_uf64 }             }
            }
        },
        std::tuple
        {
            std::vector
            {
                0xEB_b, 0xFE_b  // jmp-<-
            },
            std::vector<std::vector<std::uint_fast64_t>>
            {
                std::vector { 0_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 0_opt_uf64 } }
            }
        },
        std::tuple
        {
            std::vector
            {
                0x74_b, 0xFE_b, // je--<-
                0xC3_b          // ret
            },
            std::vector
            {
                std::vector { 0_uf64 },
                std::vector { 2_uf64 }
            },
            std::vector
            {
                std::pair { 0_uf64, std::vector { 0_opt_uf64, 2_opt_uf64 } },
                std::pair { 2_uf64, std::vector { n_opt_uf64 }             }
            }
        });

    auto const actual = dec::process(dec::program(data, dec::instruction_set_architecture::x86_32));

    SECTION("dec::process::blocks_")
    {
        REQUIRE(actual.blocks_.size() == expected_blocks.size());

        auto block_index = 0;
        for (auto const& actual_block : actual.blocks_)
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
    SECTION("dec::process::block_map_")
    {
        auto actual_block_map = actual.block_map_;

        for (auto const& [expected_address, expected_succeeding_addresses] : expected_block_map)
        {
            auto actual_block_map_entry = actual_block_map.begin();
            for (; actual_block_map_entry != actual_block_map.end(); ++actual_block_map_entry)
            {
                if (actual_block_map_entry->first->begin()->address == expected_address)
                    break;
            }

            REQUIRE(actual_block_map_entry != actual_block_map.end());

            auto actual_succeeding_blocks = actual_block_map_entry->second;
            actual_block_map.erase(actual_block_map_entry);

            for (auto const expected_succeeding_address : expected_succeeding_addresses)
            {
                auto actual_succeeding_block = actual_succeeding_blocks.begin();
                for (; actual_succeeding_block != actual_succeeding_blocks.end(); ++actual_succeeding_block)
                {
                    if ((*actual_succeeding_block == nullptr && !expected_succeeding_address) ||
                        (*actual_succeeding_block)->begin()->address == expected_succeeding_address)
                        break;
                }

                REQUIRE(actual_succeeding_block != actual_succeeding_blocks.end());

                actual_succeeding_blocks.erase(actual_succeeding_block);
            }

            CHECK(actual_succeeding_blocks.empty());
        }

        CHECK(actual_block_map.empty());
    }
}
