#pragma once

#include <generic-reveng/analysis/execution.hpp>

namespace grev
{
    class machine_monitor
    {
        execution execution_;

    public:

        template <typename Disassembler, typename Program>
        explicit machine_monitor(Disassembler const& disassembler, Program const& program);

        // >>-----
        std::vector<std::vector<std::uint32_t>> path_addresses() const; // Testing seam TODO
        // -----<<

    private:

        template <typename Program>
        static execution_state memory_patch(Program const& program, std::unordered_set<z3::expression> const& dependencies);
    };
}

#ifndef LINT
#include <generic-reveng/analysis/machine_monitor.tpp>
#endif
