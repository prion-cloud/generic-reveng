#pragma once

#include <grev/execution.hpp>
#include <grev/machine_program.hpp>

namespace grev
{
    class machine_monitor
    {
        machine_program program_;

        execution execution_;

        std::unordered_map<std::uint32_t, execution> import_cache_; // Previously executed imports to be reused
        std::unordered_map<std::uint32_t, std::forward_list<execution_state>> import_calls_; // The execution states during import calls, trimmed to the import's dependencies

    public:

        template <typename Disassembler>
        explicit machine_monitor(Disassembler const& disassembler, machine_program program);

        // >>-----
        std::vector<std::vector<std::uint32_t>> path_addresses() const; // Testing seam TODO
        // -----<<

        std::unordered_map<std::uint32_t, std::forward_list<execution_state>> const& import_calls() const;

    private:

        execution_state memory_patch(std::unordered_set<z3::expression> const& dependencies) const;
    };
}

#ifndef LINT
#include <grev/machine_monitor.tpp>
#endif
