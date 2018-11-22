#include <sstream>
#include <unordered_map>

#include "test_helper.h"

std::string to_cfg_string(cfg const& cfg)
{
    std::vector<cfg::block const*> blocks;
    for (auto const* const block : cfg)
        blocks.push_back(block);

    std::sort(blocks.begin(), blocks.end(), cfg::block::comparator());

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

            std::sort(cur_predecessors.begin(), cur_predecessors.end(), cfg::block::comparator());

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

            std::sort(cur_successors.begin(), cur_successors.end(), cfg::block::comparator());

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
