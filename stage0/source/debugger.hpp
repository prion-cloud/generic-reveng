#pragma once

#include <utility/disassembler.hpp>
#include <utility/emulator.hpp>

#include "control_flow_graph.hpp"
#include "loader.hpp"

class debugger
{
    loader loader_;

    disassembler disassembler_;
    emulator emulator_;

    control_flow_graph cfg_;

public:

    debugger();

    void load_executable_file(std::string const& path);
    void load_executable(std::vector<uint8_t> const& data);

    uint64_t position() const;

    control_flow_graph const& cfg() const;
};

static_assert(std::is_destructible_v<debugger>);

static_assert(std::is_move_constructible_v<debugger>);
static_assert(std::is_move_assignable_v<debugger>);

static_assert(!std::is_copy_constructible_v<debugger>);
static_assert(!std::is_copy_assignable_v<debugger>);
