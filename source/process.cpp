#include <decompilation/process.hpp>

#include "reil_monitor.hpp"

namespace dec
{
    process::process(std::vector<std::uint8_t> data, instruction_set_architecture const& architecture) :
        memory_(std::move(data)),
        monitor_(std::make_unique<reil_monitor>(architecture))
    {
        execute_from(0);
    }
    process::~process() = default;
    
    std::set<instruction_block, instruction_block::exclusive_address_order> const& process::blocks() const
    {
        return blocks_;
    }
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const& process::block_map() const
    {
        return block_map_;
    }

    void process::execute_from(std::uint64_t address)
    {
        // Use the start address of the next higher block as a maximum
        std::optional<std::uint64_t> max_address;
        if (auto const max_block = blocks_.lower_bound(address); max_block != blocks_.end())
            max_address = max_block->begin()->address;

        // Fill a new block with contiguous instructions
        instruction_block new_block;
        std::unordered_set<std::uint64_t> next_addresses;
        do
        {
            auto const current_instruction = new_block.insert(new_block.end(), monitor_->trace(address, memory_[address]));
            address += current_instruction->size;

            next_addresses.clear();
            if (current_instruction->step)
                next_addresses.insert(address);
            for (auto const& expr : current_instruction->ip)
            {
                if (expr.is_numeral())
                    next_addresses.insert(expr.get_numeral_uint64());
                else
                {
                    // TODO
                }
            }
        }
        while (
            // Single successor
            next_addresses.size() == 1 &&
            // Directly following
            *next_addresses.begin() == address &&
            // Block size integrity
            (!max_address || address < max_address));

        auto const& [current_block, current_block_original] =
            blocks_.insert(std::move(new_block));
        if (!current_block_original)
            throw std::logic_error("");

        auto const& [current_block_map_entry, current_block_map_entry_original] =
            block_map_.emplace(current_block->begin()->address, std::move(next_addresses));
        if (!current_block_map_entry_original)
            throw std::logic_error("");

        for (auto const& next_address : current_block_map_entry->second)
        {
            // Search for an existing block already covering the next address
            auto const existing_block = blocks_.lower_bound(next_address);

            // No block found?
            if (existing_block == blocks_.upper_bound(next_address))
            {
                // RECURSE with this successor
                execute_from(next_address);
                continue;
            }

            // Search for the respective instruction in the found block
            auto const existing_instruction = existing_block->find(next_address);
            if (existing_instruction == existing_block->end())
                throw std::logic_error("");

            // Is it the first instruction?
            if (existing_instruction == existing_block->begin())
                continue;

            auto const existing_block_hint = std::next(existing_block);

            instruction_block existing_head_block;
            auto existing_tail_block = blocks_.extract(existing_block);
            while (existing_tail_block.value().begin() != existing_instruction)
                existing_head_block.insert(
                    existing_head_block.begin(),
                    existing_tail_block.value().extract(std::prev(existing_instruction)));

            auto existing_head_block_map_entry = block_map_.extract(existing_head_block.begin()->address);
            std::pair existing_tail_block_map_entry
            {
                existing_tail_block.value().begin()->address,
                std::move(existing_head_block_map_entry.mapped())
            };
            existing_head_block_map_entry.mapped() =
                std::unordered_set
                {
                    existing_tail_block.value().begin()->address
                };

            blocks_.insert(existing_block_hint, std::move(existing_head_block));
            blocks_.insert(existing_block_hint, std::move(existing_tail_block));

            block_map_.insert(std::move(existing_head_block_map_entry));
            block_map_.insert(std::move(existing_tail_block_map_entry));
        }
    }

    std::vector<std::uint64_t>
        process::search_back(instruction const& instruction, std::string const& key) const
    {
        return { }; // TODO
    }

    static_assert(std::is_destructible_v<process>);

    static_assert(!std::is_move_constructible_v<process>); // TODO
    static_assert(!std::is_move_assignable_v<process>); // TODO

    static_assert(!std::is_copy_constructible_v<process>); // TODO
    static_assert(!std::is_copy_assignable_v<process>); // TODO
}
