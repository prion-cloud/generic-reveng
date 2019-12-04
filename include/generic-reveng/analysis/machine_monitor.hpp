#pragma once

#include <generic-reveng/analysis/execution_path.hpp>

namespace grev
{
    class machine_monitor
    {
        std::forward_list<execution_path> paths_;

    public:

        template <typename Disassembler, typename Program>
        explicit machine_monitor(Disassembler const& disassembler, Program const& program);

        // >>-----
        std::vector<std::vector<std::uint32_t>> path_addresses() const; // Testing seam TODO
        // -----<<

    private:

        template <typename Program>
        static execution_state create_memory_patch(Program const& program, std::unordered_set<z3::expression> const& dependencies);
    };
}

#ifndef LINT
#include <generic-reveng/analysis/machine_monitor.tpp>
#endif
