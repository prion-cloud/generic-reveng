#include <algorithm>
#include <optional>
#include <stack>
#include <unordered_set>

#include "../include/scout/control_flow_graph.h"

bool control_flow_graph::block_ptr_comparator::operator()(block_ptr const& block1, block_ptr const& block2) const
{
    return block1->back().address < block2->front().address;
}

bool control_flow_graph::block_ptr_comparator::operator()(block_ptr const& block, uint64_t const address) const
{
    return block->back().address < address;
}
bool control_flow_graph::block_ptr_comparator::operator()(uint64_t const address, block_ptr const& block) const
{
    return address < block->front().address;
}

control_flow_graph::control_flow_graph(debugger const& debugger)
{
    root_ = build(debugger, block_map_);
}

std::vector<control_flow_graph::block const*> control_flow_graph::get_blocks() const
{
    std::vector<block const*> blocks(block_map_.size());

    std::transform(block_map_.begin(), block_map_.end(), blocks.begin(),
        [](auto element_pair) { return element_pair.first.get(); });

    return blocks;
}

control_flow_graph::block_ptr control_flow_graph::build(debugger const& debugger,
    std::map<block_ptr, std::vector<block_ptr>, block_ptr_comparator>& block_map)
{
    // Create new basic block and successor container
    auto const new_block = std::make_shared<std::vector<machine_instruction>>();
    std::vector<block_ptr> next_blocks;

    // Current address already covered by block?
    auto const new_address = debugger.position();
    auto const block_search = block_map.lower_bound(new_address);
    if (block_search != block_map.upper_bound(new_address))
    {
        // Inquire the found block and its successors
        auto const found_block = block_search->first;

        // Find the instruction
        auto const instruction_search = std::find_if(found_block->begin(), found_block->end(),
            [new_address](auto const& instruction)
            {
                return instruction.address == new_address;
            });

        // No cut needed?
        if (instruction_search == found_block->begin())
            return found_block;

        // Instruction not found?
        if (instruction_search == found_block->end())
            throw std::logic_error("Misaligned block(s)");

        // Use original successors
        next_blocks = block_search->second;

        // Use trimmed instructions
        block_map.erase(found_block);
        new_block->assign(instruction_search, found_block->end());
        found_block->erase(instruction_search, found_block->end());
        block_map.emplace(found_block, std::vector<block_ptr> { new_block });
    }
    else
    {
        // Iterate through all contiguous instructions and store final successors
        std::vector<std::optional<uint64_t>> next_addresses;
        while (true)
        {
            auto const address = debugger.position();
            if (block_map.lower_bound(address) != block_map.upper_bound(address))
                break;

            // Store current machine instruction
            auto const cur_instruction = debugger.current_instruction();
            new_block->push_back(*cur_instruction);

            // Inquire successors
            auto const cur_disassembly = cur_instruction->disassemble();
            next_addresses = cur_disassembly.get_successors();

            // Zero or multiple successors?
            if (next_addresses.size() != 1)
                break;

            // Jump?
            auto const next_address = next_addresses.front();
            if (!next_address.has_value() ||
                *next_address != cur_disassembly->address + cur_disassembly->size)
                break;

            // Continue with successor
            debugger.position(*next_address);
        }

        // Inspect succeeding blocks
        for (auto const& address : next_addresses)
        {
            // TODO: Ambiguous jump?

            // RECURSE for each successor
            debugger.position(*address);
            next_blocks.push_back(build(debugger, block_map));
        }
    }

    // Store the new block with its successors and exit
    block_map.emplace(new_block, next_blocks);
    return new_block;
}
