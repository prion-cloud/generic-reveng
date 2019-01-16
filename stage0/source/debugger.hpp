#pragma once

#include <unordered_map>

#include <utility/disassembler.hpp>
#include <utility/emulator.hpp>

#include "control_flow_graph.hpp"

struct executable_specification
{
    machine_architecture architecture;

    uint64_t entry_point { };

    std::unordered_map<uint64_t, std::vector<uint8_t>> memory_regions;
};

class debugger
{
    disassembler disassembler_;
    emulator emulator_;

    int ip_register_;

    control_flow_graph cfg_;
    control_flow_graph::const_iterator cfg_root_;

public:

    explicit debugger(executable_specification const& specification);

    uint64_t position() const;
    void position(uint64_t address);

    std::shared_ptr<instruction> current_instruction() const;

    control_flow_graph const& cfg() const;
    control_flow_graph::value_type const& cfg_root() const;

    static std::unique_ptr<debugger> load(std::string const& file_name);
    static std::unique_ptr<debugger> load(std::istream& is);

private:

    control_flow_graph::const_iterator construct_cfg();

    control_flow_block create_block(std::vector<std::optional<uint64_t>>* next_addresses);

    std::vector<std::optional<uint64_t>> get_next_addresses(std::shared_ptr<instruction> const& instruction);

    static std::unique_ptr<debugger> load_pe(std::istream& is);
    static std::unique_ptr<debugger> load_elf(std::istream& is);
};
