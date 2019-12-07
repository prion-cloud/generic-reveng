#pragma once

#include <generic-reveng/analysis/execution.hpp>
#include <generic-reveng/analysis/machine_program.hpp>

namespace grev
{
    class machine_monitor
    {
        machine_program program_;

        execution execution_;

    public:

        template <typename Disassembler>
        explicit machine_monitor(Disassembler const& disassembler, machine_program program);

        // >>-----
        std::vector<std::vector<std::uint32_t>> path_addresses() const; // Testing seam TODO
        // -----<<

    private:

        execution_state memory_patch(std::unordered_set<z3::expression> const& dependencies) const;
    };
}

#ifndef LINT
#include <generic-reveng/analysis/machine_monitor.tpp>
#endif
