#pragma once

#include <unordered_map>
#include <unordered_set>

#include <decompilation/instruction_block.hpp>
#include <decompilation/program.hpp>

#include <reil/disassembler.hpp>

namespace dec
{
    class process
    {
    private:

        program program_;

        reil::disassembler disassembler_;

        std::set<instruction_block, instruction_block::exclusive_address_order> blocks_;
        std::unordered_map<std::uint_fast64_t, std::unordered_set<std::optional<std::uint_fast64_t>>> block_map_;

    public:

        explicit process(program program);
        ~process();

    private:

        void execute_from(std::uint_fast64_t address);

        std::unordered_set<std::optional<std::uint_fast64_t>>
            get_next_addresses(std::vector<reil_inst_t> const& reil_instructions) const;
    };
}
