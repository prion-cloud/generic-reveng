#include "control_flow_graph.hpp"

bool instruction_address_order::operator()(std::shared_ptr<instruction> const& instruction1, std::shared_ptr<instruction> const& instruction2) const
{
    return instruction1->address < instruction2->address;
}

bool instruction_address_order::operator()(std::shared_ptr<instruction> const& instruction, uint64_t const address) const
{
    return instruction->address < address;
}
bool instruction_address_order::operator()(uint64_t const address, std::shared_ptr<instruction> const& instruction) const
{
    return address < instruction->address;
}

bool control_flow_block_exclusive_address_order::operator()(control_flow_block const& block1, control_flow_block const& block2) const
{
    return (*block1.rbegin())->address < (*block2.begin())->address;
}

bool control_flow_block_exclusive_address_order::operator()(control_flow_block const& block, uint64_t const address) const
{
    return (*block.rbegin())->address < address;
}
bool control_flow_block_exclusive_address_order::operator()(uint64_t const address, control_flow_block const& block) const
{
    return address < (*block.begin())->address;
}
