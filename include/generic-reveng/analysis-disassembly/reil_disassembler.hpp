#pragma once

#include <memory>
#include <unordered_set>

#include <generic-reveng/analysis/machine_state.hpp>
#include <generic-reveng/loading/data_section.hpp>
#include <generic-reveng/loading/machine_architecture.hpp>

namespace grev
{
    class reil_disassembler
    {
        class handle;
        std::unique_ptr<handle> handle_;

    public:

        explicit reil_disassembler(machine_architecture architecture);
        ~reil_disassembler();

        std::pair<machine_state, std::optional<std::unordered_set<z3_expression>>>
            operator()(data_section* data_section, machine_state state) const;
    };
}
