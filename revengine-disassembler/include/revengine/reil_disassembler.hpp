#pragma once

#include <memory>

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

        std::optional<std::unordered_set<z3::expression, z3::expression::hash, z3::expression::equal_to>>
            operator()(data_section* data_section, machine_impact* impact) const;
    };
}
