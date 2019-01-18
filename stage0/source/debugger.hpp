#pragma once

#include <utility/disassembler.hpp>
#include <utility/emulator.hpp>

#include "control_flow_graph.hpp"

class debugger
{
    disassembler disassembler_;
    emulator emulator_;

    int ip_register_;

    control_flow_graph cfg_;
    control_flow_graph::const_iterator cfg_root_;

public:

    void load_executable_file(std::string const& path);

    uint64_t position() const;

    control_flow_graph const& cfg() const;
    control_flow_graph::value_type const& cfg_root() const;

private:

    control_flow_graph::const_iterator construct_cfg();

    control_flow_block create_block(std::vector<std::optional<uint64_t>>* next_addresses);

    std::vector<std::optional<uint64_t>> get_next_addresses(std::shared_ptr<instruction> const& instruction);
};
