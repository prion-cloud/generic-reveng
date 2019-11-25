#pragma once

#include <list>
#include <memory>

#include <generic-reveng/analysis/execution_fork.hpp>
#include <generic-reveng/analysis/execution_state.hpp>
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

        mutable execution_fork jumps_;

        mutable execution_state state_;
        mutable execution_state temporary_state_;

    public:

        explicit reil_disassembler(machine_architecture architecture);
        ~reil_disassembler();

        reil_disassembler(reil_disassembler const& other);
        reil_disassembler(reil_disassembler&& other) noexcept;

        reil_disassembler& operator=(reil_disassembler other) noexcept;

        std::pair<execution_state, execution_fork> operator()(std::uint32_t* address, std::u8string_view* data) const;

    private:

        z3::expression get_value(_reil_arg_t const& argument) const;
        void set_value(_reil_arg_t const& argument, z3::expression value) const;
    };
}
