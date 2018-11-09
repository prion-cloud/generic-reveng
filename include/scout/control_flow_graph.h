#pragma once

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include "instruction.h"

template <typename Provider>
class control_flow_graph
{
    class machine_instruction_comparator
    {
    public:

        using is_transparent = void;

        bool operator()(machine_instruction const& instruction1, machine_instruction const& instruction2) const
        {
            return instruction1.address < instruction2.address;
        }

        bool operator()(machine_instruction const& instruction, uint64_t const address) const
        {
            return instruction.address < address;
        }
        bool operator()(uint64_t const address, machine_instruction const& instruction) const
        {
            return address < instruction.address;
        }
    };

    using block = std::set<machine_instruction, machine_instruction_comparator>;
    using block_ptr = std::shared_ptr<block>;

    class block_ptr_comparator
    {
    public:

        using is_transparent = void;

        bool operator()(block_ptr const& block1, block_ptr const& block2) const
        {
            return block1->crbegin()->address < block2->cbegin()->address;
        }

        bool operator()(block_ptr const& block, uint64_t const address) const
        {
            return block->crbegin()->address < address;
        }
        bool operator()(uint64_t const address, block_ptr const& block) const
        {
            return address < block->cbegin()->address;
        }
    };

    using block_directory = std::map<block_ptr, std::vector<block_ptr>, block_ptr_comparator>;

    block_ptr entry_block_;

    block_directory block_dir_;

public:

    explicit control_flow_graph(Provider& provider)
        : entry_block_(std::make_shared<block>())
    {
        construct(provider, entry_block_);
    }

    std::vector<std::pair<block_ptr, std::vector<size_t>>> get_blocks() const
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

private:

    void construct(Provider& provider, block_ptr const& cur_block)
    {
        // Create the block through iterating over all contiguous instructions
        std::vector<std::optional<uint64_t>> next_addresses;
        while (true)
        {
            // Store current machine instruction
            auto const cur_instruction = provider.current_instruction();
            cur_block->insert(cur_block->cend(), *cur_instruction);

            // Inquire successors
            auto const cur_disassembly = cur_instruction->disassemble();
            next_addresses = cur_disassembly.get_successors();

                                                                    // Do not continue the block creation if
            if (next_addresses.empty() ||                           // - there are no successors or
                !std::all_of(                                       // - some (actual) jumps or
                    next_addresses.cbegin(), next_addresses.cend(),
                    [&cur_disassembly](auto const& address)
                    {
                        return address.has_value() &&
                            *address == cur_disassembly->address + cur_disassembly->size;
                    }) ||
                block_dir_.lower_bound(*next_addresses.front()) !=  // - the next instruction is known
                    block_dir_.upper_bound(*next_addresses.front()))
                break;

            // Continue the block creation
            provider.position(*next_addresses.front());
        }

        // Record the current block with an (so far) empty successor list
        auto const [cur_block_ref, cur_block_insertion_successful] =
            block_dir_.emplace(cur_block, std::vector<block_ptr> { });

        // ASSERT directory integrity
        if (!cur_block_insertion_successful)
            throw std::logic_error("Misaligned block(s) #" + std::to_string(__LINE__));

        auto& next_blocks = cur_block_ref->second;

        // Iterate over successor addresses
        for (auto const& next_address : next_addresses)
        {
            // TODO: Ambiguous jump?

            // Search for an existing block already covering the next address
            auto const existing_block_search = block_dir_.lower_bound(*next_address);

            // No block found?
            if (existing_block_search == block_dir_.upper_bound(*next_address))
            {
                // Create a new empty successor
                auto const next_block = std::make_shared<block>();
                next_blocks.push_back(next_block);

                // RECURSE with this block
                provider.position(*next_address);
                construct(provider, next_block);

                continue;
            }

            // Inquire the search result
            auto& [existing_block, existing_block_successors] = *existing_block_search;

            // Search for the respective instruction in the found block
            auto const instruction_search = existing_block->find(*next_address);

            // ASSERT a found instruction
            if (instruction_search == existing_block->end())
                throw std::logic_error("Misaligned block(s) #" + std::to_string(__LINE__));

            // Is it the first instruction?
            if (instruction_search == existing_block->begin())
            {
                // Use it as a successor
                next_blocks.push_back(existing_block);

                continue;
            }

            // Create a new successor by cutting off the found block's tail
            auto const next_block = std::make_shared<block>(instruction_search, existing_block->end());
            existing_block->erase(instruction_search, existing_block->end());
            next_blocks.push_back(next_block);

            // Record the successor
            auto const next_block_insertion_successful =
                block_dir_.emplace(next_block, existing_block_successors).second;

            // ASSERT directory integrity
            if (!next_block_insertion_successful)
                throw std::logic_error("Misaligned block(s) #" + std::to_string(__LINE__));

            // Update the found block's successors
            existing_block_successors = std::vector<block_ptr> { next_block };
        }
    }
};
