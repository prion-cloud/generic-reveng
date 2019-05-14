#include <algorithm>

#include <decompilation/process.hpp>

#include "execution_engine.hpp"

namespace dec
{
    process::process(program program) :
        program_(std::move(program)),
        execution_engine_(std::make_unique<execution_engine>(program_.architecture()))
    {
        execute_from(program_.start_address());

        for (auto const& block : blocks_)
        {
            auto const& tail_instruction = *block.rbegin();
            auto& successors = block_map_[&block];
            std::transform(
                tail_instruction.jumps.begin(),
                tail_instruction.jumps.end(),
                std::inserter(successors, successors.end()),
                [this](auto const& address) -> dec::instruction_block const* // NOLINT [fuchsia-trailing-return]
                {
                    if (!address)
                        return nullptr;
                    return &*blocks_.find(*address);
                });
        }
    }
    process::~process() = default;

    void process::execute_from(std::uint_fast64_t const address)
    {
        auto const [cur_block, cur_block_original] = blocks_.insert(create_block(address));
        if (!cur_block_original)
            throw std::logic_error("");

        for (auto const& next_address : cur_block->rbegin()->jumps)
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

            instruction_block existing_block_head;
            auto existing_block_tail = blocks_.extract(existing_block);
            while (existing_block_tail.value().begin() != existing_instruction)
                existing_block_head.insert(
                    existing_block_head.begin(),
                    existing_block_tail.value().extract(std::prev(existing_instruction)));

            blocks_.insert(existing_block_hint, std::move(existing_block_head));
            blocks_.insert(existing_block_hint, std::move(existing_block_tail));
        }
    }

    instruction_block process::create_block(std::uint_fast64_t address) const
    {
        // Use the start address of the next higher block as a maximum
        std::optional<uint64_t> max_address;
        if (auto const max_block = blocks_.lower_bound(address);
            max_block != blocks_.end())
            max_address = max_block->begin()->address;

        // Create a new block
        instruction_block block;

        // Fill the block with contiguous instructions
        instruction_block::iterator instruction;
        do
        {
            instruction = block.insert(block.end(), execution_engine_->disassemble(address, program_[address]));

            // Advance address
            address += instruction->size;
        }
        while (
            // Uniqueness
            instruction->jumps.size() == 1 &&
            // Unambiguity
            *instruction->jumps.begin() &&
            // Unintermediateness
            *instruction->jumps.begin() == address &&
            // Size integrity
            (!max_address || *instruction->jumps.begin() < max_address));

        return block;
    }

    static_assert(std::is_destructible_v<process>);

    static_assert(!std::is_move_constructible_v<process>); // TODO
    static_assert(!std::is_move_assignable_v<process>);    // TODO

    static_assert(!std::is_copy_constructible_v<process>); // TODO
    static_assert(!std::is_copy_assignable_v<process>);    // TODO
}
