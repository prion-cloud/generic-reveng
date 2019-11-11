#pragma once

#include <revengine/machine_impact.hpp>

namespace rev
{
    class execution_path : std::vector<std::uint64_t>
    {
        machine_impact impact_;

    public:

        void update(std::uint64_t address, machine_impact impact);

        machine_impact const& impact() const;
    };
}
