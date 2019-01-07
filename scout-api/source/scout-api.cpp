#include "../include/scout-api/scout-api.h"

#include "cfg.hpp"
#include "debugger.hpp"

void const* cfg_construct(char const* const file_name)
{
    auto debugger = debugger::load(file_name);
    return new ::cfg(debugger);
}
void cfg_destruct(void const* const cfg)
{
    delete static_cast<::cfg const*>(cfg);
}

void const* cfg_get_root(void const* const cfg)
{
    return static_cast<::cfg const*>(cfg)->root();
}

int cfg_block_count_successors(void const* const cfg_block)
{
    return static_cast<::cfg::block const*>(cfg_block)->successors.size();
}
void const* cfg_block_get_successor(void const* const cfg_block, int const index)
{
    auto successor_it = static_cast<::cfg::block const*>(cfg_block)->successors.cbegin();
    std::advance(successor_it, index);

    return *successor_it;
}

int cfg_block_count_instructions(void const* const cfg_block)
{
    return static_cast<::cfg::block const*>(cfg_block)->size();
}
void cfg_block_get_instruction(void const* const cfg_block, int const index, cs_insn* const instruction)
{
    auto instruction_it = static_cast<::cfg::block const*>(cfg_block)->cbegin();
    std::advance(instruction_it, index);

    *instruction = *instruction_it->disassemble().operator->();
}
