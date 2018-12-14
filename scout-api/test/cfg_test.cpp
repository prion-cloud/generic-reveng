#include <catch2/catch.hpp>

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "../source/cfg.hpp"

class test_provider_x86_32
{
    std::shared_ptr<csh> cs_;

    uint64_t position_;

    std::unordered_map<uint64_t, std::vector<uint8_t>> instruction_codes_;

public:

    explicit test_provider_x86_32(std::vector<std::vector<uint8_t>> const& instruction_codes);

    uint64_t position() const;
    void position(uint64_t address);

    machine_instruction current_instruction() const;
};

std::string to_cfg_string(cfg const& cfg);

TEST_CASE("Block transitioning: Linear")
{
    test_provider_x86_32 provider1(
        {
            { 0x90 }, // nop
            { 0xC3 }, // ret
            { 0xCC }  // int3
        });
    test_provider_x86_32 provider2(
        {
            { 0x90 }, // nop
            { 0xCC }, // int3
            { 0xCC }  // int3
        });
    test_provider_x86_32 provider3(
        {
            { 0x90 },       // nop
            { 0xEB, 0x00 }, // jmp +1
            { 0x90 },       // nop
            { 0xC3 }        // ret
        });
    test_provider_x86_32 provider4(
        {
            { 0x90 },       // nop
            { 0x74, 0x00 }, // je +1
            { 0x90 },       // nop
            { 0xC3 }        // ret
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

    CHECK(::to_cfg_string(cfg(provider1)) == expected1.str());
    CHECK(::to_cfg_string(cfg(provider2)) == expected2.str());
    CHECK(::to_cfg_string(cfg(provider3)) == expected3.str());
    CHECK(::to_cfg_string(cfg(provider4)) == expected4.str());
}

TEST_CASE("Block transitioning: Relocation")
{
    test_provider_x86_32 provider(
        {
            { 0x90 },       // nop
            { 0xEB, 0x01 }, // jmp +2
            { 0xCC },       // int3
            { 0x90 },       // nop
            { 0xC3 }        // ret
        });

    std::ostringstream expected;
    expected         << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 jmp 4"
        << std::endl << "-> 1"
        << std::endl
        << std::endl << "1:"
        << std::endl << "<- 0"
        << std::endl << "4 nop"
        << std::endl << "5 ret";

    CHECK(::to_cfg_string(cfg(provider)) == expected.str());
}

TEST_CASE("Block transitioning: IF-THEN-ELSE")
{ 
    test_provider_x86_32 provider(
        {
            { 0x90 },       // nop
            { 0x74, 0x03 }, // je +4
            { 0x90 },       // nop
            { 0xC3 },       // ret
            { 0xCC },       // int3
            { 0x90 },       // nop
            { 0xC3 }        // ret
        });

    std::ostringstream expected;
    expected         << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 je 6"
        << std::endl << "-> 1 2"
        << std::endl
        << std::endl << "1:"
        << std::endl << "<- 0"
        << std::endl << "3 nop"
        << std::endl << "4 ret"
        << std::endl
        << std::endl << "2:"
        << std::endl << "<- 0"
        << std::endl << "6 nop"
        << std::endl << "7 ret";

    CHECK(::to_cfg_string(cfg(provider)) == expected.str());
}

TEST_CASE("Block transitioning: IF-THEN")
{ 
    test_provider_x86_32 provider(
        {
            { 0x90 },       // nop
            { 0x75, 0x01 }, // jne +2
            { 0x90 },       // nop
            { 0x90 },       // nop
            { 0xC3 }        // ret
        });

    std::ostringstream expected;
    expected         << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 jne 4"
        << std::endl << "-> 1 2"
        << std::endl
        << std::endl << "1:"
        << std::endl << "<- 0"
        << std::endl << "3 nop"
        << std::endl << "-> 2"
        << std::endl
        << std::endl << "2:"
        << std::endl << "<- 0 1"
        << std::endl << "4 nop"
        << std::endl << "5 ret";

    CHECK(::to_cfg_string(cfg(provider)) == expected.str());
}

TEST_CASE("Block transitioning: Diamond")
{ 
    test_provider_x86_32 provider1(
        {
            { 0x90 },       // nop
            { 0x74, 0x04 }, // je +4
            { 0x90 },       // nop
            { 0xEB, 0x02 }, // jmp +3
            { 0xCC },       // int3
            { 0x90 },       // nop
            { 0x90 },       // nop
            { 0xC3 }        // ret
        });
    test_provider_x86_32 provider2(
        {
            { 0x90 },       // nop
            { 0x74, 0x04 }, // je +5
            { 0x90 },       // nop
            { 0x90 },       // nop
            { 0xC3 },       // ret
            { 0xCC },       // int3
            { 0x90 },       // nop
            { 0xEB, 0xFA }  // jmp -4
        });

    std::ostringstream expected1;
    expected1        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 je 7"
        << std::endl << "-> 1 2"
        << std::endl
        << std::endl << "1:"
        << std::endl << "<- 0"
        << std::endl << "3 nop"
        << std::endl << "4 jmp 8"
        << std::endl << "-> 3"
        << std::endl
        << std::endl << "2:"
        << std::endl << "<- 0"
        << std::endl << "7 nop"
        << std::endl << "-> 3"
        << std::endl
        << std::endl << "3:"
        << std::endl << "<- 1 2"
        << std::endl << "8 nop"
        << std::endl << "9 ret";
    std::ostringstream expected2;
    expected2        << "0:"
        << std::endl << "0 nop"
        << std::endl << "1 je 7"
        << std::endl << "-> 1 3"
        << std::endl
        << std::endl << "1:"
        << std::endl << "<- 0"
        << std::endl << "3 nop"
        << std::endl << "-> 2"
        << std::endl
        << std::endl << "2:"
        << std::endl << "<- 1 3"
        << std::endl << "4 nop"
        << std::endl << "5 ret"
        << std::endl
        << std::endl << "3:"
        << std::endl << "<- 0"
        << std::endl << "7 nop"
        << std::endl << "8 jmp 4"
        << std::endl << "-> 2";

    CHECK(::to_cfg_string(cfg(provider1)) == expected1.str());
    CHECK(::to_cfg_string(cfg(provider2)) == expected2.str());
}

TEST_CASE("Block transitioning: Loop")
{ 
    test_provider_x86_32 provider1(
        {
            { 0x90 },      // nop
            { 0xEB, 0xFD } // jmp -1
        });
    test_provider_x86_32 provider2(
        {
            { 0x90 },       // nop
            { 0x74, 0xFD }, // je -1
            { 0x90 },       // nop
            { 0xC3 }        // ret
        });
    test_provider_x86_32 provider3(
        {
            { 0x90 },      // nop
            { 0x90 },      // nop
            { 0xEB, 0xFD } // jmp -1
        });
    test_provider_x86_32 provider4(
        {
            { 0x90 },       // nop
            { 0x90 },       // nop
            { 0x74, 0xFD }, // je -1
            { 0x90 },       // nop
            { 0xC3 }        // ret
        });

    std::ostringstream expected1;
    expected1        << "0:"
        << std::endl << "<- 0"
        << std::endl << "0 nop"
        << std::endl << "1 jmp 0"
        << std::endl << "-> 0";
    std::ostringstream expected2;
    expected2        << "0:"
        << std::endl << "<- 0"
        << std::endl << "0 nop"
        << std::endl << "1 je 0"
        << std::endl << "-> 0 1"
        << std::endl
        << std::endl << "1:"
        << std::endl << "<- 0"
        << std::endl << "3 nop"
        << std::endl << "4 ret";
    std::ostringstream expected3;
    expected3        << "0:"
        << std::endl << "0 nop"
        << std::endl << "-> 1"
        << std::endl
        << std::endl << "1:"
        << std::endl << "<- 0 1"
        << std::endl << "1 nop"
        << std::endl << "2 jmp 1"
        << std::endl << "-> 1";
    std::ostringstream expected4;
    expected4        << "0:"
        << std::endl << "0 nop"
        << std::endl << "-> 1"
        << std::endl
        << std::endl << "1:"
        << std::endl << "<- 0 1"
        << std::endl << "1 nop"
        << std::endl << "2 je 1"
        << std::endl << "-> 1 2"
        << std::endl
        << std::endl << "2:"
        << std::endl << "<- 1"
        << std::endl << "4 nop"
        << std::endl << "5 ret";

    CHECK(::to_cfg_string(cfg(provider1)) == expected1.str());
    CHECK(::to_cfg_string(cfg(provider2)) == expected2.str());
    CHECK(::to_cfg_string(cfg(provider3)) == expected3.str());
    CHECK(::to_cfg_string(cfg(provider4)) == expected4.str());
}

test_provider_x86_32::test_provider_x86_32(std::vector<std::vector<uint8_t>> const& instruction_codes)
    : cs_(std::shared_ptr<csh>(new csh, cs_close)), position_(0)
{
    cs_open(CS_ARCH_X86, CS_MODE_32, cs_.get());
    cs_option(*cs_, CS_OPT_DETAIL, CS_OPT_ON);

    uint64_t address = 0;
    for (auto const& code_vector : instruction_codes)
    {
        instruction_codes_.emplace(address, code_vector);
        address += code_vector.size();
    }
}

uint64_t test_provider_x86_32::position() const
{
    return position_;
}
void test_provider_x86_32::position(uint64_t const address)
{
    position_ = address;
}

machine_instruction test_provider_x86_32::current_instruction() const
{
    auto const code_vector = instruction_codes_.at(position_);

    std::array<uint8_t, machine_instruction::SIZE> code_array;
    std::move(code_vector.cbegin(), code_vector.cend(), code_array.begin());

    return machine_instruction(cs_, position_, code_array);
}

std::string to_cfg_string(cfg const& cfg)
{
    std::vector<cfg::block const*> blocks;
    for (auto const& block : cfg)
        blocks.push_back(block.get());

    std::sort(blocks.begin(), blocks.end(), stim::wrap_comparator());

    std::unordered_map<cfg::block const*, size_t> block_indices;
    for (size_t block_index = 0; block_index < blocks.size(); ++block_index)
        block_indices.emplace(blocks.at(block_index), block_index);

    std::ostringstream cfg_ss;

    for (size_t cur_block_index = 0; cur_block_index < blocks.size(); ++cur_block_index)
    {
        if (cur_block_index > 0)
        {
            cfg_ss
                << std::endl
                << std::endl;
        }

        cfg_ss << std::dec << cur_block_index << ':';

        auto const* cur_block = blocks.at(cur_block_index);

        if (!cur_block->predecessors.empty())
        {
            std::vector<cfg::block const*> cur_predecessors(
                cur_block->predecessors.cbegin(),
                cur_block->predecessors.cend());

            std::sort(cur_predecessors.begin(), cur_predecessors.end(), stim::wrap_comparator());

            cfg_ss
                << std::endl
                << "<- ";

            for (size_t predecessor_index = 0; predecessor_index < cur_block->predecessors.size(); ++predecessor_index)
            {
                if (predecessor_index > 0)
                    cfg_ss << ' ';

                cfg_ss << std::dec << block_indices.at(cur_predecessors.at(predecessor_index));
            }
        }

        for (auto const& instruction : *cur_block)
        {
            cfg_ss
                << std::endl
                << std::hex << std::uppercase << instruction.address << ' ';

            auto const disassembly = instruction.disassemble();

            cfg_ss << disassembly->mnemonic;

            std::string const op_str = disassembly->op_str;
            if (!op_str.empty())
                cfg_ss << ' ' << op_str;
        }

        if (!cur_block->successors.empty())
        {
            std::vector<cfg::block const*> cur_successors(
                cur_block->successors.cbegin(),
                cur_block->successors.cend());

            std::sort(cur_successors.begin(), cur_successors.end(), stim::wrap_comparator());

            cfg_ss
                << std::endl
                << "-> ";

            for (size_t successor_index = 0; successor_index < cur_block->successors.size(); ++successor_index)
            {
                if (successor_index > 0)
                    cfg_ss << ' ';

                cfg_ss << std::dec << block_indices.at(cur_successors.at(successor_index));
            }
        }
    }

    return cfg_ss.str();
}
