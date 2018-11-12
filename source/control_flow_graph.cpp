#include <unordered_map>

#include "../include/scout/control_flow_graph.h"

std::vector<std::pair<control_flow_graph::block_ptr, std::vector<size_t>>> control_flow_graph::get_blocks() const
{
    std::vector<std::pair<block_ptr, std::vector<size_t>>> blocks;

    std::unordered_map<block_ptr, size_t> block_indices;
    for (auto const& [block, _] : block_dir_)
    {
        block_indices.emplace(block, blocks.size());
        blocks.emplace_back(block, std::vector<size_t> { });
    }

    for (auto& [block, successor_indices] : blocks)
    {
        for (auto const& successor : block_dir_.at(block))
            successor_indices.push_back(block_indices.at(successor));
    }

    return blocks;
}
