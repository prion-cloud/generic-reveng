#pragma once

#include <decompilation/instruction_block.hpp>
#include <decompilation/process.hpp>

namespace dec
{
    class instruction_block_graph :
        std::set<instruction_block, instruction_block::exclusive_address_order>
    {
        std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> fwd_, bwd_;

    public:

        explicit instruction_block_graph(process const& process);

        // --
        std::vector<instruction_block> blocks() const;
        std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const& block_map() const;
        std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const& block_map_reversed() const;
        // --
    };
}
