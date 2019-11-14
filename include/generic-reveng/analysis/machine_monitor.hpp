#pragma once

#include <forward_list>
#include <unordered_set>

#include <generic-reveng/analysis/execution_path.hpp>
#include <generic-reveng/loading/process.hpp>

namespace grev
{
    template <typename Disassembler>
    class machine_monitor
    {
        Disassembler disass_;

        std::forward_list<execution_path> paths_;

    public:

        explicit machine_monitor(process const& process);

        std::forward_list<execution_path> const& paths() const; // Testing seam TODO

    private:

        std::unordered_set<expression> inspect_block(data_section data_section, execution_path* path);
    };
}

#ifndef LINT
#include <generic-reveng/analysis/machine_monitor.tpp>
#endif
