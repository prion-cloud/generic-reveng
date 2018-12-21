#include "../include/scout-api/scout-api.h"

#include "cfg.hpp"
#include "debugger.hpp"

void const* create_control_flow(char const* const file_name)
{
    auto debugger = debugger::load(file_name);
    return new cfg(debugger);
}
void release_control_flow_handle(void const* const control_flow_handle)
{
    delete static_cast<cfg const*>(control_flow_handle);
}

void const* get_root_block(void const* const control_flow_handle)
{
    return static_cast<cfg const*>(control_flow_handle)->root();
}

int count_block_successors(void const* const block_handle)
{
    return static_cast<cfg::block const*>(block_handle)->successors.size();
}
void const* get_block_successor(void const* const block_handle, int const index)
{
    auto successor_it = static_cast<cfg::block const*>(block_handle)->successors.cbegin();
    std::advance(successor_it, index);

    return *successor_it;
}

int count_block_instructions(void const* const block_handle)
{
    return static_cast<cfg::block const*>(block_handle)->size();
}
void disassemble_block_instruction(void const* const block_handle, int const index, cs_insn* const instruction)
{
    auto instruction_it = static_cast<cfg::block const*>(block_handle)->cbegin();
    std::advance(instruction_it, index);

    *instruction = *instruction_it->disassemble().operator->();
}
