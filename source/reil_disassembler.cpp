#include "reil_disassembler.hpp"

int store_recent_reil_instruction(reil_inst_t* const reil_instruction, void* const reil_instructions)
{
    (*static_cast<std::unique_ptr<std::vector<reil_inst_t>>*>(reil_instructions))
        ->push_back(*reil_instruction);

    return 0;
}

namespace dec
{
    reil_disassembler::reil_disassembler(reil_arch_t const architecture) :
        reil_handle_(reil_init(architecture, store_recent_reil_instruction, &reil_instructions_)),
        reil_instructions_(std::make_unique<std::vector<reil_inst_t>>()) { }

    std::vector<reil_inst_t>
        reil_disassembler::lift(std::uint64_t const& address, std::basic_string_view<std::uint8_t> const& code) const
    {
        constexpr std::size_t max_code_size = MAX_INST_LEN;

        std::vector _code(
            code.begin(),
            std::next(
                code.begin(),
                std::min(code.size(), max_code_size)));

        reil_translate_insn(reil_handle_, address, _code.data(), _code.size());
        return std::move(*reil_instructions_);
    }

    static_assert(std::is_destructible_v<reil_disassembler>);

    static_assert(std::is_move_constructible_v<reil_disassembler>);
    static_assert(std::is_move_assignable_v<reil_disassembler>);

    static_assert(!std::is_copy_constructible_v<reil_disassembler>); // TODO
    static_assert(!std::is_copy_assignable_v<reil_disassembler>); // TODO
}
