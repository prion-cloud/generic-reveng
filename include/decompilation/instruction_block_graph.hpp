#pragma once

#include <decompilation/instruction_block.hpp>
#include <decompilation/process.hpp>

namespace dec
{
    class instruction_block_graph :
        std::set<instruction_block, instruction_block::exclusive_address_order>
    {
        std::unordered_map<std::uint64_t /*TODO block*/, std::unordered_set<std::uint64_t>> fwd_, bwd_;

        //std::unordered_set<instruction_block const*> patch_blocks_; TODO

    public:

        explicit instruction_block_graph(process const& process);

        // --
        std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const& block_map() const;
        std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const& block_map_reversed() const;
        // --

    private:

        void split(iterator const& block, std::uint64_t address);

        std::unordered_set<std::uint64_t> patch(std::uint64_t address /*TODO block*/, expression const& jump);
    };
}
