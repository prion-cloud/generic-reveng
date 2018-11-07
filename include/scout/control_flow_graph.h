#pragma once

#include <algorithm>
#include <map>
#include <memory>
#include <vector>

#include "instruction.h"

template <typename Provider>
class control_flow_graph
{
    using block = std::vector<machine_instruction>;
    using block_ptr = std::shared_ptr<block>;

    class block_ptr_comparator
    {
    public:

        using is_transparent = void;

        bool operator()(block_ptr const& block1, block_ptr const& block2) const
        {
            return block1->back().address < block2->front().address;
        }

        bool operator()(block_ptr const& block, uint64_t address) const
        {
            return block->back().address < address;
        }
        bool operator()(uint64_t address, block_ptr const& block) const
        {
            return address < block->front().address;
        }
    };

    block_ptr root_;

    std::map<block_ptr, std::vector<block_ptr>, block_ptr_comparator> block_map_;

public:

    explicit control_flow_graph(Provider& provider)
    {
        root_ = build(provider, block_map_);
    }

private:

    static block_ptr build(Provider& provider,
        std::map<block_ptr, std::vector<block_ptr>, block_ptr_comparator>& block_map)
    {
        // Create new basic block and successor container
        auto const new_block = std::make_shared<std::vector<machine_instruction>>();
        std::vector<block_ptr> next_blocks;

        // Current address already covered by block?
        auto const new_address = provider.position();
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
                auto const address = provider.position();
                if (block_map.lower_bound(address) != block_map.upper_bound(address))
                    break;

                // Store current machine instruction
                auto const cur_instruction = provider.current_instruction();
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
                provider.position(*next_address);
            }

            // Inspect succeeding blocks
            for (auto const& address : next_addresses)
            {
                // TODO: Ambiguous jump?

                // RECURSE for each successor
                provider.position(*address);
                next_blocks.push_back(build(provider, block_map));
            }
        }

        // Store the new block with its successors and exit
        block_map.emplace(new_block, next_blocks);
        return new_block;
    }
};
