#include <catch2/catch.hpp>

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <keystone/keystone.h>

#include <scout/cfg.hpp>

class test_provider_x86_32
{
    uint64_t position_;

    std::unordered_map<uint64_t, std::shared_ptr<machine_instruction>> instructions_;

public:

    explicit test_provider_x86_32(std::vector<std::string> const& instruction_strings);

    uint64_t position() const;
    void position(uint64_t const address);

    std::shared_ptr<machine_instruction> const& current_instruction() const;
};

std::string to_cfg_string(cfg const& cfg);

TEST_CASE("Block transitioning: Linear")
{
    test_provider_x86_32 provider1(
        {
            "nop",
            "ret",
            "int3"
        });
    test_provider_x86_32 provider2(
        {
            "nop",
            "int3",
            "int3"
        });
    test_provider_x86_32 provider3(
        {
            "nop",
            "jmp 3",
            "nop",
            "ret"
        });
    test_provider_x86_32 provider4(
        {
            "nop",
            "je 3",
            "nop",
            "ret"
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
            "nop",
            "jmp 4",
            "int3",
            "nop",
            "ret"
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
            "nop",
            "je 6",
            "nop",
            "ret",
            "int3",
            "nop",
            "ret"
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
            "nop",
            "jne 4",
            "nop",
            "nop",
            "ret"
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
            "nop",
            "je 7",
            "nop",
            "jmp 8",
            "int3",
            "nop",
            "nop",
            "ret"
        });
    test_provider_x86_32 provider2(
        {
            "nop",
            "je 7",
            "nop",
            "nop",
            "ret",
            "int3",
            "nop",
            "jmp 4"
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
            "nop",
            "jmp 0"
        });
    test_provider_x86_32 provider2(
        {
            "nop",
            "je 0",
            "nop",
            "ret"
        });
    test_provider_x86_32 provider3(
        {
            "nop",
            "nop",
            "jmp 1"
        });
    test_provider_x86_32 provider4(
        {
            "nop",
            "nop",
            "je 1",
            "nop",
            "ret"
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

test_provider_x86_32::test_provider_x86_32(std::vector<std::string> const& instruction_strings)
    : position_(0x0)
{
    ks_engine* ks;
    ks_open(KS_ARCH_X86, KS_MODE_32, &ks);

    auto const cs = std::shared_ptr<csh>(new csh, cs_close);
    cs_open(CS_ARCH_X86, CS_MODE_32, cs.get());
    cs_option(*cs, CS_OPT_DETAIL, CS_OPT_ON);

    uint64_t address = 0x0;
    for (auto const& instruction_string : instruction_strings)
    {
        uint8_t* code;
        size_t code_size;
        size_t stat_count;
        if (ks_asm(ks, instruction_string.c_str(), address, &code, &code_size, &stat_count) != KS_ERR_OK)
            throw std::runtime_error("Assembly failed");

        std::array<uint8_t, machine_instruction::SIZE> code_array { };
        std::move(code, code + code_size, code_array.begin());

        ks_free(code);

        instructions_.emplace(address, std::make_shared<machine_instruction>(cs, address, code_array));

        address += code_size;
    }

    ks_close(ks);
}

uint64_t test_provider_x86_32::position() const
{
    return position_;
}
void test_provider_x86_32::position(uint64_t const address)
{
    position_ = address;
}

std::shared_ptr<machine_instruction> const& test_provider_x86_32::current_instruction() const
{
    return instructions_.at(position_);
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
