#include "disassembler.hpp"

int store_recent_reil_instruction(reil_inst_t* const reil_instruction, void* const reil_instruction_vector)
{
    auto& _reil_instruction_vector =
        *static_cast<std::unique_ptr<std::vector<reil_inst_t>>*>(reil_instruction_vector);

    if (reil_instruction->inum == 0)
        _reil_instruction_vector->clear();

    _reil_instruction_vector->push_back(*reil_instruction);

    return 0;
}

namespace dec
{
    disassembler::disassembler(reil_arch_t const architecture) :
        reil_handle_(reil_init(architecture, store_recent_reil_instruction, &recent_reil_instructions_)),
        recent_reil_instructions_(std::make_unique<std::vector<reil_inst_t>>()) { }

    std::vector<reil_inst_t>
        disassembler::lift(std::uint_fast64_t const address, std::basic_string_view<std::uint_fast8_t> const& code) const
    {
        std::vector _code(code.data(),
            std::next(code.data(), std::min(code.size(), static_cast<std::size_t>(MAX_INST_LEN))));

        reil_translate_insn(reil_handle_, address, _code.data(), _code.size());
        return *recent_reil_instructions_;
    }

    static_assert(std::is_destructible_v<disassembler>);

    static_assert(std::is_move_constructible_v<disassembler>);
    static_assert(std::is_move_assignable_v<disassembler>);

    static_assert(!std::is_copy_constructible_v<disassembler>); // TODO
    static_assert(!std::is_copy_assignable_v<disassembler>); // TODO
}
