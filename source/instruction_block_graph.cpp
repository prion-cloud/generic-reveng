#include <queue>

#include <decompilation/instruction_block_graph.hpp>

namespace dec
{
    instruction_block_graph::instruction_block_graph(process const& process)
    {
        disassembler const disassembler(process.architecture());

        std::queue<std::uint64_t> address_queue;
        address_queue.push(process.start_address());

        std::unordered_multimap<instruction_block const*, expression const&> xx;
        do
        {
            for (auto it = xx.begin(); it != xx.end(); it = xx.erase(it))
            {
//                auto const variables = it->second.foo();
//                auto const x = jump.to_string(); // --

//                std::queue<instruction_block const*> aq2;
//                aq2.push(it->first);
//                do
//                {
//                    //auto const& instruction = *find(aq2.front())->find(aq2.front());
//                    auto const& block = *aq2.front();
//                    aq2.pop();
//
//                    for (auto const& variable : variables)
//                    {
//                        auto const& i = block.impact(variable);
//
//
//                    }
//
//                    // TODO
//                }
//                while (!aq2.empty());
            }

            while (!address_queue.empty())
            {
                auto const address = address_queue.front();
                address_queue.pop();

                auto const existing_block = lower_bound(address);

                if (existing_block != upper_bound(address))
                {
                    auto const existing_instruction = existing_block->find(address);

                    // Is it the first instruction?
                    if (existing_instruction == existing_block->begin())
                        continue;

                    auto const block_hint = std::next(existing_block);

                    auto tail_block = extract(existing_block);
                    auto head_block = tail_block.value().extract_head(existing_instruction); // switch head/tail?

                    auto head_fwd_entry = std::pair
                    {
                        head_block.address(),
                        std::unordered_set { tail_block.value().address() }
                    };
                    auto tail_fwd_entry = std::pair
                    {
                        tail_block.value().address(),
                        std::move(fwd_.extract(head_block.address()).mapped())
                    };

                    auto head_bwd_entry = std::pair
                    {
                        head_block.address(),
                        std::move(bwd_.extract(head_block.address()).mapped())
                    };
                    auto tail_bwd_entry = std::pair
                    {
                        tail_block.value().address(),
                        std::move(bwd_.extract(tail_block.value().address()).mapped())
                    };
                    tail_bwd_entry.second.insert(head_block.address());

                    insert(block_hint, std::move(head_block));
                    insert(block_hint, std::move(tail_block));

                    fwd_.insert(std::move(head_fwd_entry));
                    fwd_.insert(std::move(tail_fwd_entry));

                    bwd_.insert(std::move(head_bwd_entry));
                    bwd_.insert(std::move(tail_bwd_entry));

                    continue;
                }

                fwd_.try_emplace(address);
                bwd_.try_emplace(address);

                auto data_section = process[address];
                if (existing_block != end())
                    data_section.data.remove_suffix(address + data_section.data.size() - existing_block->address());

                auto const& block = *emplace(disassembler, data_section).first;

                for (auto const& jump : block.jump())
                {
                    auto const next_address = jump.evaluate();

                    if (next_address)
                    {
                        address_queue.push(*next_address);

                        fwd_[address].insert(*next_address);
                        bwd_[*next_address].insert(address);
                    }
//                    else
//                        xx.emplace(block, jump);
                }
            }
        }
        while (!xx.empty());
    }

    std::vector<instruction_block> instruction_block_graph::blocks() const
    {
        return std::vector(begin(), end());
    }
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const&
        instruction_block_graph::block_map() const
    {
//        auto block_map = fwd_;
//        for (auto const& block : *this)
//            block_map[block.address()];

        return fwd_;
    }
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const&
        instruction_block_graph::block_map_reversed() const
    {
//        auto block_map_reversed = bwd_;
//        for (auto const& block : *this)
//            block_map_reversed[block.address()];

        return bwd_;

//        std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> block_map_reversed;
//        for (auto const& [address, succeeding_addresses] : block_map_)
//        {
//            block_map_reversed.try_emplace(address); // --
//            for (auto const& succeeding_address : succeeding_addresses)
//                block_map_reversed[succeeding_address].insert(address);
//        }
//
//        return block_map_reversed;
    }

    static_assert(std::is_destructible_v<instruction_block_graph>);

    static_assert(std::is_move_constructible_v<instruction_block_graph>);
    static_assert(std::is_move_assignable_v<instruction_block_graph>);

    static_assert(std::is_copy_constructible_v<instruction_block_graph>);
    static_assert(std::is_copy_assignable_v<instruction_block_graph>);
}
