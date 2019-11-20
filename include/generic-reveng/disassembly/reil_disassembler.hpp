#pragma once

#include <memory>

#include <generic-reveng/analysis/data_section.hpp>
#include <generic-reveng/analysis/machine_architecture.hpp>
#include <generic-reveng/analysis/machine_state_update.hpp>

namespace grev
{
    class reil_disassembler
    {
        class handle;
        std::unique_ptr<handle> handle_;

    public:

        explicit reil_disassembler(machine_architecture architecture);
        ~reil_disassembler();

        machine_state_update operator()(data_section* data_section) const;
    };
}
