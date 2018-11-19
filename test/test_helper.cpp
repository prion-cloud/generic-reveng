#include <sstream>
#include <unordered_map>

#include "test_helper.h"

std::string to_cfg_string(control_flow_graph const& cfg)
{
    std::vector<control_flow_graph::block const*> blocks;
    std::unordered_map<control_flow_graph::block const*, size_t> block_indices;
    for (auto const* block : cfg)
    {
        block_indices.emplace(block, blocks.size());
        blocks.push_back(block);
    }

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

        auto const successors = cur_block->successors();

        if (!successors.empty())
        {
            cfg_ss
                << std::endl
                << "-> ";
        }

        for (size_t next_block_index = 0; next_block_index < successors.size(); ++next_block_index)
        {
            if (next_block_index > 0)
                cfg_ss << ' ';

            cfg_ss << std::dec << block_indices.at(successors.at(next_block_index));
        }
    }

    return cfg_ss.str();
}
