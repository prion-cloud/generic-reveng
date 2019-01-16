#pragma once

#include <unordered_map>

#include <utility/disassembler.hpp>
#include <utility/emulator.hpp>

#include "control_flow_graph.hpp"

struct executable
{
    machine_architecture architecture;

    uint64_t entry_point;

    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> sections;

    static std::unique_ptr<executable const> load_pe(std::vector<char> const& data);
};

class debugger
{
    disassembler disassembler_;
    emulator emulator_;

    int ip_register_;

    control_flow_graph cfg_;
    control_flow_graph::const_iterator cfg_root_;

public:

    explicit debugger(executable const& executable);

    uint64_t position() const;
    void position(uint64_t address);

    std::shared_ptr<instruction> current_instruction() const;

    control_flow_graph const& cfg() const;
    control_flow_graph::value_type const& cfg_root() const;

    static std::unique_ptr<debugger const> load_file(std::string const& file_name);

private:

    control_flow_graph::const_iterator construct_cfg();

    control_flow_block create_block(std::vector<std::optional<uint64_t>>* next_addresses);

    std::vector<std::optional<uint64_t>> get_next_addresses(std::shared_ptr<instruction> const& instruction);
};
