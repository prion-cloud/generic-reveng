#pragma once

#include <functional>
#include <unordered_set>
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

    std::unordered_set<std::optional<uint64_t>> called_addresses_;
    std::unordered_set<std::optional<uint64_t>> jumped_addresses_;

public:

    using base::base;

    control_flow_block(disassembler const& disassembler, uint64_t address, std::optional<uint64_t> const& max_address,
        std::basic_string_view<uint8_t> code);

    std::unordered_set<std::optional<uint64_t>> const& called_addresses() const;
    std::unordered_set<std::optional<uint64_t>> const& jumped_addresses() const;
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

    iterator root_;

    std::unordered_set<std::optional<uint64_t>> called_addresses_;

public:

    using base::base;

    control_flow_graph(disassembler const& disassembler,
        std::function<std::basic_string_view<uint8_t>(uint64_t)> const& GET_MEMORY, uint64_t address);

    node const& root() const;

    std::unordered_set<std::optional<uint64_t>> const& called_addresses() const;

private:

    iterator construct(disassembler const& disassembler,
        std::function<std::basic_string_view<uint8_t>(uint64_t)> const& GET_MEMORY, uint64_t address);
};

static_assert(std::is_destructible_v<control_flow_block>);

static_assert(std::is_move_constructible_v<control_flow_block>);
static_assert(std::is_move_assignable_v<control_flow_block>);

static_assert(std::is_copy_constructible_v<control_flow_block>);
static_assert(std::is_copy_assignable_v<control_flow_block>);

static_assert(std::is_destructible_v<control_flow_graph>);

static_assert(std::is_move_constructible_v<control_flow_graph>);
static_assert(std::is_move_assignable_v<control_flow_graph>);

static_assert(std::is_copy_constructible_v<control_flow_graph>);
static_assert(std::is_copy_assignable_v<control_flow_graph>);
