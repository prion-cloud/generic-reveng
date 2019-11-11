#pragma once

#include <unordered_set>

#include <revengine/machine_impact.hpp>

namespace rev
{
    class execution_path : std::vector<std::uint64_t>
    {
        std::unordered_set<std::uint64_t> address_registry_;

        machine_impact impact_;

    public:

        bool update(std::uint64_t address, machine_impact impact);

        machine_impact const& impact() const;
    };
}
