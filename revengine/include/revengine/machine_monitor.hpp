#pragma once

#include <revengine/execution_path.hpp>
#include <revengine/process.hpp>

namespace rev
{
    class machine_monitor
    {
        std::vector<execution_path> paths_;

        std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> block_map_;

    public:

        template <typename Disassembler>
        machine_monitor(Disassembler const& disass, process const& process);

        std::vector<execution_path> const& paths() const;
    };
}

#ifndef LINT
#include <revengine/machine_monitor.tpp>
#endif
