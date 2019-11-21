#pragma once

#include <memory>

#include <generic-reveng/analysis/data_section.hpp>
#include <generic-reveng/analysis/machine_architecture.hpp>
#include <generic-reveng/analysis/machine_state_update.hpp>

struct _reil_inst_t;

namespace grev
{
    class reil_disassembler
    {
        void* reil_;

        mutable std::vector<_reil_inst_t> current_reil_instructions_;

    public:

        explicit reil_disassembler(machine_architecture architecture);
        ~reil_disassembler();

        machine_state_update operator()(data_section* data_section) const;

    private:

        std::vector<_reil_inst_t> disassemble(data_section const& data_section) const;
    };
}
