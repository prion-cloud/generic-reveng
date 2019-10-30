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

        machine_impact operator()(data_section* data_section) const;
    };
}
