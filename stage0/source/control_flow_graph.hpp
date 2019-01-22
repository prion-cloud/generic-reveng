#pragma once

#include <functional>
#include <set>
#include <vector>

#include <utility/disassembler.hpp>

#include "graph.hpp"

struct instruction_address_order
{
    using is_transparent = std::true_type;

    bool operator()(std::shared_ptr<instruction const> const& instructionA,
        std::shared_ptr<instruction const> const& instructionB) const;

    bool operator()(std::shared_ptr<instruction const> const& instruction, uint64_t address) const;
    bool operator()(uint64_t address, std::shared_ptr<instruction const> const& instruction) const;
};

class control_flow_block : public std::set<std::shared_ptr<instruction const>, instruction_address_order>
{
    using base = std::set<std::shared_ptr<instruction const>, instruction_address_order>;

public:

    using base::base;

    control_flow_block(disassembler const& disassembler, uint64_t address, uint64_t max_address,
        std::basic_string_view<uint8_t> code);

    std::vector<std::optional<uint64_t>> get_next_addresses() const;
};

struct control_flow_block_exclusive_address_order
{
    using is_transparent = std::true_type;

    bool operator()(control_flow_block const& blockA, control_flow_block const& blockB) const;

    bool operator()(control_flow_block const& block, uint64_t address) const;
    bool operator()(uint64_t address, control_flow_block const& block) const;
};

class control_flow_graph : public graph<control_flow_block, control_flow_block_exclusive_address_order>
{
    using base = graph<control_flow_block, control_flow_block_exclusive_address_order>;

    disassembler disassembler_;

    std::function<std::basic_string_view<uint8_t>(uint64_t)> GET_MEMORY_; // TODO

    node const* root_;

public:

    using base::base;

    control_flow_graph(disassembler disassembler, std::function<std::basic_string_view<uint8_t>(uint64_t)> GET_MEMORY,
        uint64_t address);

    node const& root() const;

private:

    node const& construct(uint64_t address);
};
