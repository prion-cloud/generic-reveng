#pragma once

#include <set>

#include <utility/disassembler.hpp>

#include "graph.hpp"

struct instruction_address_order
{
    using is_transparent = std::true_type;

    bool operator()(std::shared_ptr<instruction> const& instruction1, std::shared_ptr<instruction> const& instruction2) const;

    bool operator()(std::shared_ptr<instruction> const& instruction, uint64_t address) const;
    bool operator()(uint64_t address, std::shared_ptr<instruction> const& instruction) const;
};

using control_flow_block = std::set<std::shared_ptr<instruction>, instruction_address_order>;

struct control_flow_block_exclusive_address_order
{
    using is_transparent = std::true_type;

    bool operator()(control_flow_block const& a, control_flow_block const& b) const;

    bool operator()(control_flow_block const& block, uint64_t address) const;
    bool operator()(uint64_t address, control_flow_block const& block) const;
};

using control_flow_graph = graph<control_flow_block, control_flow_block_exclusive_address_order>;
