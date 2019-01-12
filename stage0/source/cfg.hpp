#pragma once

#include <algorithm>
#include <memory>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <capstone/capstone.h>
#include <stimpak/comparison.hpp>

class cfg
{
    struct machine_instruction_compare
    {
        using is_transparent = void;

        bool operator()(cs_insn const& ins1, cs_insn const& ins2) const;

        bool operator()(cs_insn const& ins, uint64_t address) const;
        bool operator()(uint64_t address, cs_insn const& ins) const;
    };

public:

    struct block : std::set<cs_insn, machine_instruction_compare>
    {
        std::unordered_set<block*> successors;
        std::unordered_set<block*> predecessors;

        bool operator<(block const& other) const;

        friend bool operator<(block const& block, uint64_t address);
        friend bool operator<(uint64_t address, block const& block);
    };

private:

    block const* root_;

    std::set<std::unique_ptr<block>, sti::wrap_comparator> blocks_ { };

public:

    template <typename Provider>
    explicit cfg(Provider& provider);

    block const* root() const;

    decltype(blocks_.begin()) begin() const;
    decltype(blocks_.end()) end() const;

private:

    template <typename Provider>
    block* construct(Provider& provider);

    std::vector<std::optional<uint64_t>> get_next_addresses(cs_insn const& instruction);
};

template <typename Provider>
cfg::cfg(Provider& provider)
{
    root_ = construct(provider);
}

template <typename Provider>
cfg::block* cfg::construct(Provider& provider)
{
    // Create a new block
    auto new_block = std::make_unique<block>();

    // Fill the block with contiguous instructions
    std::vector<std::optional<uint64_t>> next_addresses;
    while (true)
    {
        // Store current machine instruction
        auto const cur_instruction = provider.current_instruction();
        new_block->insert(new_block->cend(), cur_instruction);

        // Inquire successors
        next_addresses = get_next_addresses(cur_instruction);

        // Interrupt the block creation if...
        if (next_addresses.empty() ||                       // - there are no successors or
            !std::all_of(                                   // - some (actual) jumps or
                next_addresses.cbegin(), next_addresses.cend(),
                [&cur_instruction](auto const& address)
                {
                    return address.has_value() &&
                        *address == cur_instruction.address + cur_instruction.size;
                }) ||
            blocks_.lower_bound(*next_addresses.front()) != // - the next instruction is known
                blocks_.upper_bound(*next_addresses.front()))
            break;

        // Continue the block creation
        provider.position(*next_addresses.front());
    }

    // Record the new block
    auto* const current_block = blocks_.insert(std::move(new_block)).first->get();

    // Iterate over successor addresses
    for (auto const& next_address : next_addresses)
    {
        // TODO: Ambiguous jump?

        block* next_block;

        // Search for an existing block already covering the next address
        auto const existing_block_search = blocks_.lower_bound(*next_address);

        // No block found?
        if (existing_block_search == blocks_.upper_bound(*next_address))
        {
            // RECURSE with this successor
            provider.position(*next_address);
            next_block = construct(provider);
        }
        else
        {
            // Inquire the search result
            auto* const existing_block = existing_block_search->get();

            // Search for the respective instruction in the found block
            auto const instruction_search = existing_block->find(*next_address);

            // ASSERT a found instruction
            if (instruction_search == existing_block->end())
                throw std::logic_error("Overlapping instructions");

            // Is it the first instruction?
            if (instruction_search == existing_block->begin())
            {
                // Use the found block as a successor
                next_block = existing_block;
            }
            else
            {
                // Create a new block
                auto new_block = std::make_unique<block>();

                // Dissect the found block
                new_block->insert(instruction_search, existing_block->end());
                existing_block->erase(instruction_search, existing_block->end());

                // Record the new block
                next_block = blocks_.insert(std::move(new_block)).first->get();

                // Take the found block's successors
                next_block->successors = existing_block->successors;
                for (auto* const successor : next_block->successors)
                {
                    successor->predecessors.erase(existing_block);
                    successor->predecessors.insert(next_block);
                }

                // Special case
                if (existing_block == current_block)
                {
                    existing_block->successors.clear();
                    next_block->successors.insert(next_block);
                    next_block->predecessors = { next_block };
                }
                else
                {
                    existing_block->successors = { next_block };
                    next_block->predecessors = { existing_block };
                }
            }
        }

        // Add successor
        current_block->successors.insert(next_block);
        next_block->predecessors.insert(current_block);
    }

    return current_block;
}
