#pragma once

#include <memory>
#include <unordered_set>

#include <revengine/data_section.hpp>
#include <revengine/machine_architecture.hpp>
#include <revengine/machine_impact.hpp>

namespace rev::dis
{
    class reil_disassembler
    {
        class handle;
        std::unique_ptr<handle> handle_;

    public:

        explicit reil_disassembler(machine_architecture architecture);
        ~reil_disassembler();

        std::pair<machine_impact, std::optional<std::unordered_set<rev::z3::expression>>>
            operator()(data_section* data_section, machine_impact impact) const;
    };
}
