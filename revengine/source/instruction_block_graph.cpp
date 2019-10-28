#include <queue>

#include <revengine/instruction_block_graph.hpp>

namespace rev
{
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const&
        instruction_block_graph::block_map() const
    {
        return fwd_;
    }
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const&
        instruction_block_graph::block_map_reversed() const
    {
        return bwd_;
    }

    bool instruction_block_graph::split(std::uint64_t const address)
    {
        auto const block = lower_bound(address);

        if (block == upper_bound(address))
            return false;

        auto const instruction = block->find(address);

        if (instruction == block->begin()) // TODO replace opaquely
            return true;

        // TODO tidy up

        auto const block_hint = std::next(block);

        auto tail_block = extract(block);
        auto head_block = tail_block.value().extract_head(instruction); // switch head/tail?

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

        return true;
    }

    std::unordered_set<std::uint64_t> instruction_block_graph::patch(std::uint64_t address, expression const& jump)
    {
        if (jump)
            return { *jump };

        auto const unknowns = jump.decompose();

        std::vector<expression_composition> monitors;
        std::queue<std::pair<std::uint64_t, expression_composition&>> q;

        for (auto const preceeding_address : bwd_.at(address))
        {
            monitors.emplace_back();
            q.emplace(preceeding_address, monitors.back());
        }

        while (!q.empty())
        {
            address = q.front().first;
            auto& monitor = q.front().second;
            q.pop();

            auto block_impact = find(address)->impact();
            block_impact.update(monitor);
            monitor = block_impact;

//            if (monitor[unknown].evaluate()) TODO early stop
//                continue;

            auto preceeding_addresses = bwd_.at(address);

            if (preceeding_addresses.empty())
                continue;

            auto const first_preceeding_address = preceeding_addresses.begin();
            q.emplace(*first_preceeding_address, monitor);
            preceeding_addresses.erase(first_preceeding_address);

            for (auto const preceeding_address : preceeding_addresses)
            {
                monitors.push_back(monitor);
                q.emplace(preceeding_address, monitors.back());
            }
        }

        std::unordered_set<std::uint64_t> next_addresses;
        for (auto const& monitor : monitors)
        {
            auto patched_jump = jump;
            for (auto const& unknown : unknowns)
                patched_jump = patched_jump.resolve(unknown, monitor[unknown]);

            if (patched_jump)
                next_addresses.insert(*patched_jump);
        }

        return next_addresses;
    }

    static_assert(std::is_destructible_v<instruction_block_graph>);

    static_assert(std::is_move_constructible_v<instruction_block_graph>);
    static_assert(std::is_move_assignable_v<instruction_block_graph>);

    static_assert(std::is_copy_constructible_v<instruction_block_graph>);
    static_assert(std::is_copy_assignable_v<instruction_block_graph>);
}
