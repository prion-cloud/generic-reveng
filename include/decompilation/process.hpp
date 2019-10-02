#pragma once

#include <decompilation/instruction_block.hpp>
#include <decompilation/instruction_set_architecture.hpp>
#include <decompilation/memory.hpp>

namespace dec
{
    class reil_monitor;

    class process
    {
        memory memory_;

        std::unique_ptr<reil_monitor const> monitor_;

        std::set<instruction_block, instruction_block::exclusive_address_order> blocks_;
        std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> block_map_;

    public:

        process(std::vector<std::uint8_t> data, instruction_set_architecture const& architecture); // TODO Real loading mechanism
        ~process();

        std::set<instruction_block, instruction_block::exclusive_address_order> const& blocks() const;
        std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> const& block_map() const;

    private:

        void execute_from(std::uint64_t address);

        std::vector<std::uint64_t>
            search_back(instruction const& instruction, std::string const& key) const;
    };
}
