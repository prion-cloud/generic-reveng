#include <queue>

#ifdef LINT
#include <revengine/instruction_block_graph.hpp>
#endif

namespace rev
{
    template <typename Disassembler>
    instruction_block_graph::instruction_block_graph(Disassembler const& disassembler, process const& process)
    {
        std::queue<std::uint64_t> address_queue;
        address_queue.push(process.start_address());
        do
        {
            auto const address = address_queue.front();
            address_queue.pop();

            if (split(address))
                continue;

            fwd_.try_emplace(address);
            bwd_.try_emplace(address);

            auto data_section = process[address];
            if (auto const existing_block = lower_bound(address); existing_block != end())
                data_section.data.remove_suffix(address + data_section.data.size() - existing_block->address());

            auto const& block = *emplace(disassembler, data_section).first;
            auto const block_impact = block.impact();

            std::unordered_set<std::uint64_t> next_addresses;
            for (auto const& jump : block_impact.jump())
                next_addresses.merge(patch(address, jump));
            for (auto const next_address : next_addresses)
            {
                address_queue.push(next_address);

                fwd_[address].insert(next_address);
                bwd_[next_address].insert(address);
            }
        }
        while (!address_queue.empty());
    }
}

#ifdef LINT
#include <revengine/reil_disassembler.hpp>
template rev::instruction_block_graph::instruction_block_graph(rev::dis::reil_disassembler const&, rev::process const&);
#endif
