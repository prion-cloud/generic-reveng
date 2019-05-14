#pragma once

#include <memory>
#include <unordered_map>

#include <decompilation/instruction_block.hpp>
#include <decompilation/program.hpp>

namespace dec
{
    class execution_engine;

    class process
    {
    private:

        program program_;

        std::unique_ptr<execution_engine> execution_engine_;

        std::set<instruction_block, instruction_block::exclusive_address_order> blocks_;
        std::unordered_map<instruction_block const*, std::unordered_set<instruction_block const*>> block_map_;

    public:

        explicit process(program program);
        ~process();

    private:

        void execute_from(std::uint_fast64_t address);

        instruction_block create_block(std::uint_fast64_t address) const;
    };
}
