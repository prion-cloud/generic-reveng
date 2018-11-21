#pragma once

#include <algorithm>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "instruction.h"

class cfg
{
public:

    class block;

private:

    using block_ptr = std::shared_ptr<block>;

    struct machine_instruction_comparator
    {
        using is_transparent = void;

        bool operator()(machine_instruction const& instruction1, machine_instruction const& instruction2) const;

        bool operator()(machine_instruction const& instruction, uint64_t address) const;
        bool operator()(uint64_t address, machine_instruction const& instruction) const;
    };

public:

    class block : public std::set<machine_instruction, machine_instruction_comparator>
    {
    public:

        struct comparator
        {
            using is_transparent = void;

            template <typename BlockWrapper1, typename BlockWrapper2>
            bool operator()(BlockWrapper1 const& block1, BlockWrapper2 const& block2) const;

            template <typename BlockWrapper>
            bool operator()(BlockWrapper const& block, uint64_t address) const;
            template <typename BlockWrapper>
            bool operator()(uint64_t address, BlockWrapper const& block) const;
        };

    private:

        cfg const* cfg_;

    public:

        explicit block(cfg const* cfg);

        std::vector<block const*> successors() const;
    };

    class bfs_iterator
    {
        cfg const* base_;

        block const* cur_block_;

        std::queue<block const*> block_queue_;
        std::unordered_set<block const*> previous_blocks_;

    public:

        bfs_iterator() = default;
        bfs_iterator(cfg const* base, block const* cur_block);

        bool operator==(bfs_iterator const& other) const;
        bool operator!=(bfs_iterator const& other) const;

        bfs_iterator& operator++();

        block const* const& operator*() const;
    };

private:

    block const* root_;

    std::map<block_ptr, std::vector<block const*>, block::comparator> block_map_;

public:

    template <typename Provider>
    explicit cfg(Provider& provider);

    bfs_iterator begin() const;
    bfs_iterator end() const;

    block const* root() const;

    std::vector<std::vector<block const*>> get_layout() const;

private:

    template <typename Provider>
    block const* construct(Provider& provider);

    std::unordered_map<block const*, size_t> get_depths() const;
    void get_depths(block const* root,
        std::unordered_map<block const*, size_t>& depths,
        std::unordered_set<block const*>& visited) const;
};

template <typename BlockWrapper1, typename BlockWrapper2>
bool cfg::block::comparator::operator()(BlockWrapper1 const& block1, BlockWrapper2 const& block2) const
{
    return block1->crbegin()->address < block2->cbegin()->address;
}

template <typename BlockWrapper>
bool cfg::block::comparator::operator()(BlockWrapper const& block, uint64_t const address) const
{
    return block->crbegin()->address < address;
}
template <typename BlockWrapper>
bool cfg::block::comparator::operator()(uint64_t const address, BlockWrapper const& block) const
{
    return address < block->cbegin()->address;
}

template <typename Provider>
cfg::cfg(Provider& provider)
{
    root_ = construct(provider);
}

template <typename Provider>
cfg::block const* cfg::construct(Provider& provider)
{
    // Create a new block
    auto const cur_block = std::make_shared<block>(this);

    // Fill the block with contiguous instructions
    std::vector<std::optional<uint64_t>> next_addresses;
    while (true)
    {
        // Store current machine instruction
        auto const cur_instruction = provider.current_instruction();
        cur_block->insert(cur_block->cend(), *cur_instruction);

        // Inquire successors
        auto const cur_disassembly = cur_instruction->disassemble();
        next_addresses = cur_disassembly.get_successors();

        // Interrupt the block creation if
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

    // Record the current block
    auto& next_blocks = block_map_[cur_block];

    // Iterate over successor addresses
    for (auto const& next_address : next_addresses)
    {
        // TODO: Ambiguous jump?

        // Search for an existing block already covering the next address
        auto const existing_block_search = block_map_.lower_bound(*next_address);

        // No block found?
        if (existing_block_search == block_map_.upper_bound(*next_address))
        {
            // RECURSE with a successor
            provider.position(*next_address);
            next_blocks.push_back(construct(provider));

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
            // Use the found block as a successor
            next_blocks.push_back(existing_block.get());

            continue;
        }

        // Create a new successor by cutting off the found block's tail
        auto const next_block = std::make_shared<block>(this);
        next_block->insert(instruction_search, existing_block->end());
        existing_block->erase(instruction_search, existing_block->end());
        next_blocks.push_back(next_block.get());

        // Record the successor
        block_map_[next_block] = existing_block_successors;

        // Update the found block's successors
        existing_block_successors.assign({ next_block.get() });
    }

    return cur_block.get();
}
