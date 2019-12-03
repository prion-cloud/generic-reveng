#pragma once

#include <list>
#include <memory>

#include <generic-reveng/analysis/execution_update.hpp>
#include <generic-reveng/analysis/machine_architecture.hpp>

struct _reil_arg_t;
struct _reil_inst_t;

namespace grev
{
    class reil_disassembler
    {
        machine_architecture architecture_;
        void* handle_;

        mutable std::list<_reil_inst_t> instructions_;

        mutable execution_update update_;
        mutable execution_state temporary_state_;

    public:

        explicit reil_disassembler(machine_architecture architecture);
        ~reil_disassembler();

        reil_disassembler(reil_disassembler const& other);
        reil_disassembler(reil_disassembler&& other) noexcept;

        reil_disassembler& operator=(reil_disassembler other) noexcept;

        execution_update operator()(std::uint32_t* address, std::u8string_view* code) const;

    private:

        void jump(_reil_arg_t const& argument, z3::expression value, z3::expression* step_condition) const;

        z3::expression get_value(_reil_arg_t const& argument) const;
        void set_value(_reil_arg_t const& argument, z3::expression value) const;
    };
}
