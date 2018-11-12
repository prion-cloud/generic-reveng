#pragma once

#include <algorithm>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <unordered_set>
#include <vector>

#include "instruction.h"

class control_flow_graph
{
    class machine_instruction_comparator;

public:

    using block = std::set<machine_instruction, machine_instruction_comparator>;

private:

    using block_ptr = std::shared_ptr<block>;

    class machine_instruction_comparator
    {
    public:

        using is_transparent = void;

        bool operator()(machine_instruction const& instruction1, machine_instruction const& instruction2) const;

        bool operator()(machine_instruction const& instruction, uint64_t address) const;
        bool operator()(uint64_t address, machine_instruction const& instruction) const;
    };
    class block_ptr_comparator
    {
    public:

        using is_transparent = void;

        bool operator()(block_ptr const& block1, block_ptr const& block2) const;

        bool operator()(block_ptr const& block1, block const* block2) const;
        bool operator()(block const* block1, block_ptr const& block2) const;

        bool operator()(block_ptr const& block, uint64_t address) const;
        bool operator()(uint64_t address, block_ptr const& block) const;
    };

public:

    class bfs_iterator
    {
    public:

        using difference_type = ptrdiff_t;
        using value_type = block const*;
        using pointer = block const* const*;
        using reference = block const* const&;
        using iterator_category = std::forward_iterator_tag;

    private:

        control_flow_graph const* base_;

        value_type cur_block_;

        std::queue<block const*> block_queue_;
        std::unordered_set<block const*> previous_blocks_;

    public:

        bfs_iterator() = default;
        bfs_iterator(control_flow_graph const* base, block const* cur_block);

        bool operator==(bfs_iterator const& other) const;
        bool operator!=(bfs_iterator const& other) const;

        bfs_iterator& operator++();

        reference operator*() const;
    };

private:

    block_ptr first_block_;

    std::map<block_ptr, std::vector<block_ptr>, block_ptr_comparator> block_map_;

public:

    template <typename Provider>
    explicit control_flow_graph(Provider& provider);

    bfs_iterator begin() const;
    bfs_iterator end() const;

    std::vector<block const*> get_successors(block const* block) const;

private:

    template <typename Provider>
    void construct(Provider& provider, block_ptr const& cur_block);
};

template <typename Provider>
control_flow_graph::control_flow_graph(Provider& provider)
    : first_block_(std::make_shared<block>())
{
    construct(provider, first_block_);
}

template <typename Provider>
void control_flow_graph::construct(Provider& provider, block_ptr const& cur_block)
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
            block_map_.lower_bound(*next_addresses.front()) !=  // - the next instruction is known
                block_map_.upper_bound(*next_addresses.front()))
            break;

        // Continue the block creation
        provider.position(*next_addresses.front());
    }

    // Record the current block with an (so far) empty successor list
    auto const [cur_block_ref, cur_block_insertion_successful] =
        block_map_.emplace(cur_block, std::vector<block_ptr> { });

    // ASSERT directory integrity
    if (!cur_block_insertion_successful)
        throw std::logic_error("Misaligned block(s) #" + std::to_string(__LINE__));

    auto& next_blocks = cur_block_ref->second;

    // Iterate over successor addresses
    for (auto const& next_address : next_addresses)
    {
        // TODO: Ambiguous jump?

        // Search for an existing block already covering the next address
        auto const existing_block_search = block_map_.lower_bound(*next_address);

        // No block found?
        if (existing_block_search == block_map_.upper_bound(*next_address))
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
        auto const next_block_recording_successful =
            block_map_.emplace(next_block, existing_block_successors).second;

        // ASSERT directory integrity
        if (!next_block_recording_successful)
            throw std::logic_error("Misaligned block(s) #" + std::to_string(__LINE__));

        // Update the found block's successors
        existing_block_successors = std::vector<block_ptr> { next_block };
    }
}
