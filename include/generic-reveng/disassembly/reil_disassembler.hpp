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
        machine_architecture architecture_;

        void* reil_;
        std::unique_ptr<std::list<_reil_inst_t>> current_reil_instructions_;

    public:

        explicit reil_disassembler(machine_architecture architecture);
        ~reil_disassembler();

        reil_disassembler(reil_disassembler const& other);
        reil_disassembler(reil_disassembler&& other) noexcept;

        reil_disassembler& operator=(reil_disassembler other) noexcept;

        machine_state_update operator()(data_section* data_section) const;

    private:

        std::list<_reil_inst_t> disassemble(data_section const& data_section) const;
    };
}
