#pragma once

#include <unordered_set>

#include <generic-reveng/analysis/machine_state.hpp>

namespace grev
{
    class execution_path : std::vector<std::uint64_t>
    {
        std::unordered_set<std::uint64_t> address_registry_;

        machine_state state_;

    public:

        bool update(std::uint64_t address, machine_state state);

        machine_state const& state() const;
    };
}
