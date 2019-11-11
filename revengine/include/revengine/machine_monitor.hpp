#pragma once

#include <forward_list>
#include <unordered_set>

#include <revengine/execution_path.hpp>
#include <revengine/process.hpp>

namespace rev
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

        std::unordered_set<z3::expression> inspect_block(data_section data_section, execution_path* path);
    };
}

#ifndef LINT
#include <revengine/machine_monitor.tpp>
#endif
