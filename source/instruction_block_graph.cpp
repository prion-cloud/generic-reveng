#include <stack>

#include <decompilation/instruction_block_graph.hpp>

namespace dec
{
    instruction_block_graph::instruction_block_graph(process const& process)
    {
        disassembler const disassembler(process.architecture());

        std::stack<std::uint64_t> address_stack;
        address_stack.push(process.start_address());
        do
        {
            auto const address = address_stack.top();
            address_stack.pop();

            auto const existing_block = lower_bound(address);

            if (existing_block != upper_bound(address))
            {
                auto const existing_instruction = existing_block->find(address);

                // Is it the first instruction?
                if (existing_instruction == existing_block->begin())
                    continue;

                auto const existing_block_hint = std::next(existing_block);

                auto existing_tail_block = extract(existing_block);
                auto existing_head_block = existing_tail_block.value().extract_head(existing_instruction);

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

                insert(existing_block_hint, std::move(existing_head_block));
                insert(existing_block_hint, std::move(existing_tail_block));

                block_map_.insert(std::move(existing_head_block_map_entry));
                block_map_.insert(std::move(existing_tail_block_map_entry));

                continue;
            }

            auto data_section = process[address];
            if (existing_block != end())
                data_section.data.remove_suffix(address + data_section.data.size() - existing_block->begin()->address);

            instruction_block new_block(disassembler, data_section);

            std::unordered_set<std::uint64_t> next_addresses;
            for (auto const& jump : new_block.rbegin()->jump)
            {
                if (jump.has_value())
                {
                    next_addresses.insert(jump.value());
                    continue;
                }

                // TODO
            }

            for (auto const& next_address : next_addresses)
                address_stack.push(next_address);

            insert(std::move(new_block));

            block_map_.emplace(address, std::move(next_addresses));
        }
        while (!address_stack.empty());
    }

    std::vector<instruction_block> instruction_block_graph::blocks() const
    {
        return std::vector(begin(), end());
    }
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const& instruction_block_graph::block_map() const
    {
        return block_map_;
    }

    static_assert(std::is_destructible_v<instruction_block_graph>);

    static_assert(std::is_move_constructible_v<instruction_block_graph>);
    static_assert(std::is_move_assignable_v<instruction_block_graph>);

    static_assert(std::is_copy_constructible_v<instruction_block_graph>);
    static_assert(std::is_copy_assignable_v<instruction_block_graph>);
}
