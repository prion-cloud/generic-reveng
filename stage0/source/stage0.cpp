#include "../include/stage0/stage0.h"

#include "debugger.hpp"

void const* cfg_construct(char const* const file_name)
{
    return debugger::load(file_name).release();
}
void cfg_destruct(void const* const cfg)
{
    delete static_cast<debugger const*>(cfg); // NOLINT [cppcoreguidelines-owning-memory]
}

void const* cfg_get_root(void const* const cfg)
{
    return &static_cast<debugger const*>(cfg)->cfg_root();
}

int cfg_block_count_successors(void const* const cfg_block)
{
    return static_cast<control_flow_graph::value_type const*>(cfg_block)->second.size();
}
void const* cfg_block_get_successor(void const* const cfg_block, int const index)
{
    auto successor_it = static_cast<control_flow_graph::value_type const*>(cfg_block)->second.begin();
    std::advance(successor_it, index);

    return *successor_it;
}

int cfg_block_count_instructions(void const* const cfg_block)
{
    return static_cast<control_flow_graph::value_type const*>(cfg_block)->first.size();
}
void cfg_block_get_instruction(void const* const cfg_block, int const index, cs_insn* const instruction)
{
    auto instruction_it = static_cast<control_flow_graph::value_type const*>(cfg_block)->first.begin();
    std::advance(instruction_it, index);

    *instruction = **instruction_it;
}
