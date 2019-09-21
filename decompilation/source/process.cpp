#include <algorithm>

#include <decompilation/process.hpp>

#include "common_exception.hpp"

reil_arch_t to_reil(dec::instruction_set_architecture const architecture)
{
    switch (architecture)
    {
        case dec::instruction_set_architecture::x86_32:
        case dec::instruction_set_architecture::x86_64:
            return ARCH_X86;

        // TODO
    }

    throw unknown_architecture();
}

namespace dec
{
    process::process(program program) :
        program_(std::move(program)),
        disassembler_(to_reil(program_.architecture()))
    {
        execute_from(program_.start_address());
    }
    process::~process() = default;

    void process::execute_from(std::uint_fast64_t address)
    {
        // Use the start address of the next higher block as a maximum
        std::optional<uint64_t> max_address;
        if (auto const max_block = blocks_.lower_bound(address);
            max_block != blocks_.end())
            max_address = max_block->begin()->address;

        // Fill a new block with contiguous instructions
        instruction_block new_block;
        std::unordered_set<std::optional<std::uint_fast64_t>> next_addresses;
        do
        {
            auto const reil_instructions = disassembler_(address, program_[address]);

            next_addresses = get_next_addresses(reil_instructions);

            instruction const instruction
            {
                .address = reil_instructions.front().raw_info.addr,
                .size = static_cast<std::size_t>(reil_instructions.front().raw_info.size)
            };

            new_block.insert(new_block.end(), instruction);
            address += instruction.size;
        }
        while (
            // Uniqueness
            next_addresses.size() == 1 &&
            // Unambiguity
            *next_addresses.begin() &&
            // Unintermediateness
            *next_addresses.begin() == address &&
            // Size integrity
            (!max_address || *next_addresses.begin() < max_address));

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
            // Ambiguous jump?
            if (!next_address)
            {
                // TODO
                continue;
            }

            // Search for an existing block already covering the next address
            auto const existing_block = blocks_.lower_bound(*next_address);

            // No block found?
            if (existing_block == blocks_.upper_bound(*next_address))
            {
                // RECURSE with this successor
                execute_from(*next_address);
                continue;
            }

            // Search for the respective instruction in the found block
            auto const existing_instruction = existing_block->find(*next_address);
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
                std::unordered_set<std::optional<std::uint_fast64_t>> { existing_tail_block.value().begin()->address };

            blocks_.insert(existing_block_hint, std::move(existing_head_block));
            blocks_.insert(existing_block_hint, std::move(existing_tail_block));

            block_map_.insert(std::move(existing_head_block_map_entry));
            block_map_.insert(std::move(existing_tail_block_map_entry));
        }
    }

    std::unordered_set<std::optional<std::uint_fast64_t>>
        process::get_next_addresses(std::vector<reil_inst_t> const& reil_instructions) const
    {
        std::unordered_set<std::optional<std::uint_fast64_t>> next_addresses;

        auto step = true;

        for (auto const& reil_instruction : reil_instructions)
        {
            switch (reil_instruction.op)
            {
            case I_UNK:
                step = false;
                break;
            case I_JCC:
                switch (reil_instruction.c.type)
                {
                case A_LOC:
                    next_addresses.insert(reil_instruction.c.val);
                    break;
                default:
                    next_addresses.insert(std::nullopt); // TODO
                    break;
                }

                step = reil_instruction.a.type != A_CONST || reil_instruction.a.val == 0;
                break;
            default:
                break;
            }

            if (!step)
                break;
        }

        if (step)
            next_addresses.insert(reil_instructions.front().raw_info.addr + reil_instructions.front().raw_info.size);

        return next_addresses;
    }

    static_assert(std::is_destructible_v<process>);

    static_assert(!std::is_move_constructible_v<process>); // TODO
    static_assert(!std::is_move_assignable_v<process>); // TODO

    static_assert(!std::is_copy_constructible_v<process>); // TODO
    static_assert(!std::is_copy_assignable_v<process>); // TODO
}
