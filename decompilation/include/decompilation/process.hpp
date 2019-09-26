#pragma once

#include <memory>
#include <unordered_set>

#include <decompilation/instruction_block.hpp>
#include <decompilation/instruction_set_architecture.hpp>
#include <decompilation/memory.hpp>

namespace dec
{
    class disassembler;
    class monitor;

    class process
    {
        memory memory_;

        std::unique_ptr<disassembler const> disassembler_;
        std::unique_ptr<monitor> monitor_;

        std::set<instruction_block, instruction_block::exclusive_address_order> blocks_;
        std::unordered_map<std::uint_fast64_t, std::unordered_set<std::uint_fast64_t>> block_map_;

    public:

        process(std::vector<std::uint_fast8_t> data, instruction_set_architecture architecture); // TODO Real loading mechanism
        ~process();

        std::set<instruction_block, instruction_block::exclusive_address_order> const& blocks() const;
        std::unordered_map<std::uint_fast64_t, std::unordered_set<std::uint_fast64_t>> const& block_map() const;

    private:

        void execute_from(std::uint_fast64_t address);

        std::vector<std::uint_fast64_t>
            search_back(instruction const& instruction, std::string const& key) const;
    };
}
